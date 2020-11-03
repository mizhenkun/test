#define _GNU_SOURCE
#include <sched.h>
#include <unistd.h> /* sysconf */
#include <stdlib.h> /* exit */
#include <stdio.h>

int main(void)
{
    int i, nrcpus;
    cpu_set_t mask;
    unsigned long bitmask = 0;
    
    CPU_ZERO(&mask);
    
    CPU_SET(0, &mask); /* add CPU0 to cpu set */
    CPU_SET(2, &mask); /* add CPU2 to cpu set */

      /* Set the CPU affinity for a pid */
    if (sched_setaffinity(0, sizeof(cpu_set_t), &mask) == -1) 
    {   
        perror("sched_setaffinity");
        exit(EXIT_FAILURE);
    }
    
    CPU_ZERO(&mask);
    
     /* Get the CPU affinity for a pid */
    if (sched_getaffinity(0, sizeof(cpu_set_t), &mask) == -1) 
    {   
        perror("sched_getaffinity");
        exit(EXIT_FAILURE);
    }




	printf("%d ******\n", sched_getaffinity(0, sizeof(cpu_set_t), &mask));


       /* get logical cpu number */
    nrcpus = sysconf(_SC_NPROCESSORS_CONF);
    
    for (i = 0; i < nrcpus; i++)
    {
        if (CPU_ISSET(i, &mask))
        {
            bitmask |= (unsigned long)0x01 << i;
            printf("processor #%d is set\n", i); 
        }
    }
    printf("bitmask = %#lx\n", bitmask);

    exit(EXIT_SUCCESS);
}
