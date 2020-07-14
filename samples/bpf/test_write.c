#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

/*
 * argument 1: device where program will be attached (ie. /dev/sda)
 * argument 2: path where test file will be created to check IO
*/
int main(int argc, char **argv)
{
	int fd, ret;

	if (argc != 2){
		printf("Invalid number of arguments\n");
		return 1;
	}

	fd = open(argv[1], O_WRONLY|O_CREAT|O_TRUNC, 0666);

	if (fd == -1)
		printf("Failed to create test file %s\n", argv[1]);
	else
		printf("Opened file \"%s\" successfully.\n", argv[1]);

	ret = write(fd, "test_write \n", 12);

	if (ret == -1)
		printf("Failed to write to test file.\n");
	else
		printf("Wrote to test file.\n");

	ret = fsync(fd);

	if (ret == -1)
		printf("fsync failed.\n");
	else
		printf("fsync succeeded.\n");

	close(fd);

	printf("Exiting user program.\n");

	return 0;
}

