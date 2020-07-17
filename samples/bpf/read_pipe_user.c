#define _GNU_SOURCE

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/bpf.h>
#include "trace_helpers.h"
#include "bpf_load.h"

/*
 * user program to load bpf program, protect_gpt_kern, to prevent writing to GUID
 * parititon table
 *
 * argument 1: device where program will be attached (ie. /dev/sda)
*/
int main(int argc, char **argv)
{
	read_trace_pipe();
	return 0;
}

