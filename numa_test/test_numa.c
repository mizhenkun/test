#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sched.h>
#include <dirent.h>
#include <errno.h>
#include <stdarg.h>
#include <ctype.h>

#include <sys/mman.h>
#include <limits.h>

#define __NR_sched_setaffinity    203
#define __NR_sched_getaffinity    204
#define __NR_get_mempolicy 239
#define WEAK __attribute__((weak))

#define howmany(x,y) (((x)+((y)-1))/(y))
#define bitsperlong (8 * sizeof(unsigned long))
#define bitsperint (8 * sizeof(unsigned int))
#define longsperbits(n) howmany(n, bitsperlong)

#define round_up(x,y) (((x) + (y) - 1) & ~((y)-1))
#define BITS_PER_LONG (sizeof(unsigned long) * 8)
#define CPU_BYTES(x) (round_up(x, BITS_PER_LONG)/8)
#define CPU_LONGS(x) (CPU_BYTES(x) / sizeof(long))


static int cpumask_sz = 0;
static int maxconfigurednode = -1;
static char node_cpu_mask_v2_stale = 1;
static struct bitmask *numa_memnode_ptr = NULL;
static struct bitmask *numa_nodes_ptr = NULL;
static struct bitmask **node_cpu_mask_v2;
static int nodemask_sz = 0;
static const char *mask_size_file = "/proc/self/status";
static const char *nodemask_prefix = "Mems_allowed:\t";

struct bitmask {
	unsigned long size; /* number of bits in the map */
	unsigned long *maskp;
};

unsigned int numa_bitmask_nbytes(struct bitmask *bmp)
{
	return longsperbits(bmp->size) * sizeof(unsigned long);
}

int numa_sched_getaffinity_v2(pid_t pid, struct bitmask *mask)
{
	/* len is length in bytes */
	return syscall(__NR_sched_getaffinity, pid, numa_bitmask_nbytes(mask),
								mask->maskp);
	/* sched_getaffinity returns sizeof(cpumask_t) */

}

/* where n is the number of bits in the map */
/* This function should not exit on failure, but right now we cannot really
   recover from this. */
struct bitmask *numa_bitmask_alloc(unsigned int n)
{
	struct bitmask *bmp;

	if (n < 1) {
		errno = EINVAL;
		printf("request to allocate mask for invalid number");
		exit(1);
	}
	bmp = malloc(sizeof(*bmp));
	if (bmp == 0)
		goto oom;
	bmp->size = n;
	bmp->maskp = calloc(longsperbits(n), sizeof(unsigned long));
	if (bmp->maskp == 0) {
		free(bmp);
		goto oom;
	}
	return bmp;

oom:
	printf("Out of memory allocating bitmask");
	exit(1);
}


void numa_bitmask_free(struct bitmask *bmp)
{
	if (bmp == 0)
		return;
	free(bmp->maskp);
	bmp->maskp = (unsigned long *)0xdeadcdef;  /* double free tripwire */
	free(bmp);
	return;
}

/*
 * Find the highest cpu number possible (in other words the size
 * of a kernel cpumask_t (in bits) - 1)
 */
static void set_numa_max_cpu(void)
{
	int len = 4096;
	int n;
	int olde = errno;
	struct bitmask *buffer;

	do {
		buffer = numa_bitmask_alloc(len);
		n = numa_sched_getaffinity_v2(0, buffer);
		/* on success, returns size of kernel cpumask_t, in bytes */
		if (n < 0) {
			if (errno == EINVAL) {
				if (len >= 1024*1024)
					break;
				len *= 2;
				numa_bitmask_free(buffer);
				continue;
			} else {
				printf("Unable to determine max cpu (sched_getaffinity: %s); guessing...",
					  strerror(errno));
				n = sizeof(cpu_set_t);
				break;
			}
		}
	} while (n < 0);
	numa_bitmask_free(buffer);
	errno = olde;
	cpumask_sz = n*8;
}

int numa_num_possible_cpus(void)
{
	return cpumask_sz;
}

int numa_num_possible_nodes(void)
{
	return nodemask_sz;
}


/*
 * Return the number of the highest node in this running system,
 */
int
numa_max_node(void)
{
	return maxconfigurednode;
}


/* Is string 'pre' a prefix of string 's'? */
static int strprefix(const char *s, const char *pre)
{
	return strncmp(s, pre, strlen(pre)) == 0;
}

/*
 * Convert the string length of an ascii hex mask to the number
 * of bits represented by that mask.
 */
static int s2nbits(const char *s)
{
	return strlen(s) * 32 / 9;
}


long WEAK get_mempolicy(int *policy, unsigned long *nmask,
				unsigned long maxnode, void *addr,
				unsigned flags)
{
	return syscall(__NR_get_mempolicy, policy, nmask,
					maxnode, addr, flags);
}

/*
 * (do this the way Paul Jackson's libcpuset does it)
 * The nodemask values in /proc/self/status are in an
 * ascii format that uses 9 characters for each 32 bits of mask.
 * (this could also be used to find the cpumask size)
 */
static void set_nodemask_size(void)
{
	FILE *fp;
	char *buf = NULL;
	size_t bufsize = 0;

	if ((fp = fopen(mask_size_file, "r")) == NULL)
		goto done;

	while (getline(&buf, &bufsize, fp) > 0) {
		if (strprefix(buf, nodemask_prefix)) {
			nodemask_sz = s2nbits(buf + strlen(nodemask_prefix));
			break;
		}
	}
	free(buf);
	fclose(fp);
done:
	if (nodemask_sz == 0) {/* fall back on error */
		int pol;
		unsigned long *mask = NULL;
		nodemask_sz = 16;
		do {
			nodemask_sz <<= 1;
			mask = realloc(mask, nodemask_sz / 8);
			if (!mask)
				return;
		} while (get_mempolicy(&pol, mask, nodemask_sz + 1, 0, 0) < 0 && errno == EINVAL &&
				nodemask_sz < 4096*8);
		free(mask);
	}
}


int numa_max_possible_node_v2(void)
{
	return numa_num_possible_nodes()-1;
}

/*
 * Allocate a bitmask for nodes, of a size large enough to
 * match the kernel's nodemask_t.
 */
struct bitmask *numa_allocate_nodemask(void)
{
	struct bitmask *bmp;
	int nnodes = numa_max_possible_node_v2() + 1;

	bmp = numa_bitmask_alloc(nnodes);
	return bmp;
}


static void
_setbit(struct bitmask *bmp, unsigned int n, unsigned int v)
{
	if (n < bmp->size) {
		if (v)
			bmp->maskp[n/bitsperlong] |= 1UL << (n % bitsperlong);
		else
			bmp->maskp[n/bitsperlong] &= ~(1UL << (n % bitsperlong));
	}
}


/*
 * The following bitmask declarations, bitmask_*() routines, and associated
 * _setbit() and _getbit() routines are:
 * Copyright (c) 2004_2007 Silicon Graphics, Inc. (SGI) All rights reserved.
 * SGI publishes it under the terms of the GNU General Public License, v2,
 * as published by the Free Software Foundation.
 */
static unsigned int _getbit(const struct bitmask *bmp, unsigned int n)
{
	if (n < bmp->size)
		return (bmp->maskp[n/bitsperlong] >> (n % bitsperlong)) & 1;
	else
		return 0;
}

struct bitmask *numa_bitmask_setbit(struct bitmask *bmp, unsigned int i)
{
	_setbit(bmp, i, 1);
	return bmp;
}


int numa_bitmask_isbitset(const struct bitmask *bmp, unsigned int i)
{
	return _getbit(bmp, i);
}


/* (cache the result?) */
long long numa_node_size64(int node, long long *freep)
{
	size_t len = 0;
	char *line = NULL;
	long long size = -1;
	FILE *f;
	char fn[64];
	int ok = 0;
	int required = freep ? 2 : 1;

	if (freep)
		*freep = -1;
	sprintf(fn,"/sys/devices/system/node/node%d/meminfo", node);
	f = fopen(fn, "r");
	if (!f)
		return -1;
	while (getdelim(&line, &len, '\n', f) > 0) {
		char *end;
		char *s = strcasestr((const char*)line, (const char*)"kB");
		if (!s)
			continue;
		--s;
		while (s > line && isspace(*s))
			--s;
		while (s > line && isdigit(*s))
			--s;
		if (strstr(line, "MemTotal")) {
			size = strtoull(s,&end,0) << 10;
			if (end == s)
				size = -1;
			else
				ok++;
		}
		if (freep && strstr(line, "MemFree")) {
			*freep = strtoull(s,&end,0) << 10;
			if (end == s)
				*freep = -1;
			else
				ok++;
		}
	}
	fclose(f);
	free(line);
	if (ok != required)
		printf("Cannot parse sysfs meminfo (%d)", ok);
	return size;
}


/*
 * Find nodes (numa_nodes_ptr), nodes with memory (numa_memnode_ptr)
 * and the highest numbered existing node (maxconfigurednode).
 */
static void set_configured_nodes(void)
{
	DIR *d;
	struct dirent *de;
	long long freep;

	numa_memnode_ptr = numa_allocate_nodemask();
	numa_nodes_ptr = numa_allocate_nodemask();

	d = opendir("/sys/devices/system/node");
	if (!d) {
		maxconfigurednode = 0;
	} else {
		while ((de = readdir(d)) != NULL) {
			int nd;
			if (strncmp(de->d_name, "node", 4))
				continue;
			nd = strtoul(de->d_name+4, NULL, 0);
			numa_bitmask_setbit(numa_nodes_ptr, nd);
			if (numa_node_size64(nd, &freep) > 0)
				numa_bitmask_setbit(numa_memnode_ptr, nd);
			if (maxconfigurednode < nd)
				maxconfigurednode = nd;
		}
		closedir(d);
	}
}

static void init_node_cpu_mask_v2(void)
{
	int nnodes = numa_max_possible_node_v2() + 1;
	node_cpu_mask_v2 = calloc (nnodes, sizeof(struct bitmask *));
}


struct bitmask *numa_bitmask_clearall(struct bitmask *bmp)
{
	unsigned int i;
	for (i = 0; i < bmp->size; i++)
		_setbit(bmp, i, 0);
	return bmp;
}


/*
 * copy a bitmask map body to another bitmask body
 * fill a larger destination with zeroes
 */
void copy_bitmask_to_bitmask(struct bitmask *bmpfrom, struct bitmask *bmpto)
{
	int bytes;

	if (bmpfrom->size >= bmpto->size) {
		memcpy(bmpto->maskp, bmpfrom->maskp, CPU_BYTES(bmpto->size));
	} else if (bmpfrom->size < bmpto->size) {
		bytes = CPU_BYTES(bmpfrom->size);
		memcpy(bmpto->maskp, bmpfrom->maskp, bytes);
		memset(((char *)bmpto->maskp)+bytes, 0, CPU_BYTES(bmpto->size)-bytes);
	}
}


/*
 * Allocate a bitmask for cpus, of a size large enough to
 * match the kernel's cpumask_t.
 */
struct bitmask *numa_allocate_cpumask()
{
	int ncpus = numa_num_possible_cpus();

	return numa_bitmask_alloc(ncpus);
}


struct bitmask *numa_bitmask_setall(struct bitmask *bmp)
{
	unsigned int i;
	for (i = 0; i < bmp->size; i++)
		_setbit(bmp, i, 1);
	return bmp;
}

int numa_parse_bitmap_v2(char *line, struct bitmask *mask)
{
	int i, ncpus;
	char *p = strchr(line, '\n');
	if (!p)
		return -1;
	ncpus = mask->size;

	for (i = 0; p > line;i++) {
		char *oldp, *endp;
		oldp = p;
		if (*p == ',')
			--p;
		while (p > line && *p != ',')
			--p;
		/* Eat two 32bit fields at a time to get longs */
		if (p > line && sizeof(unsigned long) == 8) {
			oldp--;
			memmove(p, p+1, oldp-p+1);
			while (p > line && *p != ',')
				--p;
		}
		if (*p == ',')
			p++;
		if (i >= CPU_LONGS(ncpus))
			return -1;
		mask->maskp[i] = strtoul(p, &endp, 16);
		if (endp != oldp)
			return -1;
		p--;
	}
	return 0;
}


/*
 * test whether a node has cpus
 */
/* This would be better with some locking, but I don't want to make libnuma
   dependent on pthreads right now. The races are relatively harmless. */
/*
 * deliver a bitmask of cpus representing the cpus on a given node
 */
int numa_node_to_cpus_v2(int node, struct bitmask *buffer)
{
	int err = 0;
	int nnodes = numa_max_node();
	char fn[64], *line = NULL;
	FILE *f;
	char update;
	size_t len = 0;
	struct bitmask *mask;

	if (!node_cpu_mask_v2)
		init_node_cpu_mask_v2();

	if (node > nnodes) {
		errno = ERANGE;
		return -1;
	}
	numa_bitmask_clearall(buffer);

	update = __atomic_fetch_and(&node_cpu_mask_v2_stale, 0, __ATOMIC_RELAXED);
	if (node_cpu_mask_v2[node] && !update) {
		/* have already constructed a mask for this node */
		if (buffer->size < node_cpu_mask_v2[node]->size) {
			errno = EINVAL;
			printf("map size mismatch");
			return -1;
		}
		copy_bitmask_to_bitmask(node_cpu_mask_v2[node], buffer);
		return 0;
	}

	/* need a new mask for this node */
	mask = numa_allocate_cpumask();

	/* this is a kernel cpumask_t (see node_read_cpumap()) */
	sprintf(fn, "/sys/devices/system/node/node%d/cpumap", node);
	f = fopen(fn, "r");
	if (!f || getdelim(&line, &len, '\n', f) < 1) {
		if (numa_bitmask_isbitset(numa_nodes_ptr, node)) {
			printf("/sys not mounted or invalid. Assuming one node: %s\n",
				  strerror(errno));
			printf("(cannot open or correctly parse %s)\n", fn);
		}
		numa_bitmask_setall(mask);
		err = -1;
	}
	if (f)
		fclose(f);

	if (line && (numa_parse_bitmap_v2(line, mask) < 0)) {
		printf("Cannot parse cpumap. Assuming one node\n");
		numa_bitmask_setall(mask);
		err = -1;
	}

	free(line);
	copy_bitmask_to_bitmask(mask, buffer);

	/* slightly racy, see above */
	/* save the mask we created */
	if (node_cpu_mask_v2[node]) {
		if (update) {
			copy_bitmask_to_bitmask(mask, node_cpu_mask_v2[node]);
			numa_bitmask_free(mask);
			mask = NULL;
		/* how could this be? */
		} else if (mask != buffer)
			numa_bitmask_free(mask);
	} else {
		/* we don't want to cache faulty result */
		if (!err)
			node_cpu_mask_v2[node] = mask;
		else
			numa_bitmask_free(mask);
	}
	return err;
}


/* report the node of the specified cpu */
int numa_node_of_cpu(int cpu)
{
	struct bitmask *bmp;
	int ncpus, nnodes, node, ret;

	ncpus = numa_num_possible_cpus();
	if (cpu > ncpus){
		errno = EINVAL;
		return -1;
	}
	bmp = numa_bitmask_alloc(ncpus);
	nnodes = numa_max_node();
	for (node = 0; node <= nnodes; node++){
		if (numa_node_to_cpus_v2(node, bmp) < 0) {
			/* It's possible for the node to not exist */
			continue;
		}
		if (numa_bitmask_isbitset(bmp, cpu)){
			ret = node;
			goto end;
		}
	}
	ret = -1;
	errno = EINVAL;
end:
	numa_bitmask_free(bmp);
	return ret;
}

int main()
{
	int cpu, node;
	set_numa_max_cpu();
	set_nodemask_size();
	set_configured_nodes();

	cpu = sched_getcpu();
	node = numa_node_of_cpu(cpu);

	printf("cpu = %d\n", cpu);
	printf("node = %d\n", node);

	return 0;
}
