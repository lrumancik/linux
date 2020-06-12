#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include "trace_helpers.h"
#include "bpf_load.h"

int main(int argc, char **argv)
{
	char filename[256], test_file[256];
	int fd, ret;

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);

	if (load_bpf_file(filename)) {
		printf("error loading program: %s\n", bpf_log_buf);
		return 1;
	}

	printf("loaded kprobe/submit_bio program successfully\n");

	strcpy(test_file, getenv("HOME"));
	strcat(test_file, "/kprobe_test");

	fd = open(test_file, O_WRONLY|O_CREAT|O_TRUNC, S_IRWXU|S_IRWXG|S_IRWXO);

	if (!fd)
		printf("failed to create test file\n");
	else
		printf("opened file successfully\n");

	ret = write(fd, "hello", 5);

	if (!ret)
		printf("failed to write to test file\n");
	else
		printf("wrote to test file\n");

	ret = fsync(fd);

	if (ret == -1)
		printf("fsync failed\n");
	else
		printf("fsync succeeded\n");

	close(fd);

	read_trace_pipe();

	printf("exiting user program\n");

	return 0;
}

