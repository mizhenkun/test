#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>

int main()
{
	int fd;
	int ret;

	fd = open("/dev/mzk", O_RDWR);
	if (fd < 0) {
		perror("fail to open\n");
		return -1;
	}

	ret = ioctl(fd, 880904, NULL);
	if (ret < 0) {
		perror("fail to unpin\n");
		return -1;
	}

	return 0;
}
