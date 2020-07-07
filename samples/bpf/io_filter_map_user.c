#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <string.h>
#include "trace_helpers.h"
#include "bpf_load.h"

/*
 * Functionality:
 *	Attach: load program and attach io filter to device
 *		pin program and map to a given destination
 *	Update: update map used to control which regions of io are filtered
 *	Detach: detach program from device
 *		unpin program and map
 * Arguments:
 *	arg 1: device where program will be attached (ie. /dev/sda)
 *	arg 2: name for pinned object (ie. io_filter)
 *		will create /sys/fs/bpf/[name] and /sys/fs/bpf/[name]_map objects
 *	arg 3: --attach, --detach, or --update
 *	arg 4: if --update, follow by
 *		<allow/block> <start_sector> <num_sectors>
 *		ex) --update block 0 10	//blocks io to first 10 sectors
 */

#define ATTACH 0
#define UPDATE 1
#define DETACH 2

static int attach(char *dev, char *pin_path)
{
	struct bpf_object *obj;
	int ret, ret_pin_prog, ret_pin_map, progfd, mapfd, devfd;
	uint32_t index, val;
	char prog_path[256];
	char map_path[256];

	strcpy(prog_path, "/sys/fs/bpf/");
	strcat(prog_path, pin_path);

	strcpy(map_path, prog_path);
	strcat(map_path, "_map");

	progfd = bpf_obj_get(prog_path);
	mapfd = bpf_obj_get(map_path);
	if (progfd >= 0 || mapfd >= 0) {
		fprintf(stderr, "Error: object already pinned at given location\n");
		return 1;
	}

	ret = bpf_prog_load("io_filter_map_kern.o",
			    BPF_PROG_TYPE_IO_FILTER, &obj, &progfd);
	if (ret) {
		fprintf(stderr, "Error: failed to load io_filter_map_kern program\n");
		return 1;
	}

	mapfd = bpf_object__find_map_fd_by_name(obj, "control");
	if (mapfd < 0) {
		fprintf(stderr, "Error: failed to retrieve map\n");
		return 1;
	}

	/* initialize map to allow io */
	/* is this necessary? */
	val = 0;
	for (int i = 0; i < 65535; i++) {
		index = i;
		ret = bpf_map_update_elem(mapfd, &index, &val, BPF_ANY);
		if (ret)
			fprintf(stderr, "Error:failed to update map element\n");
	}

	devfd = open(dev, O_RDONLY);
	if (devfd == -1) {
		fprintf(stderr, "Error: failed to open block device %s\n", dev);
		return 1;
	}

	ret = bpf_prog_attach(progfd, devfd, BPF_BIO_SUBMIT, 0);
	if (ret) {
		fprintf(stderr, "Error: failed to attach bpf io_filter_map to device\n");
		close(devfd);
		return 1;
	}
	printf("Attached bpf io_filter_map program to device %s.\n", dev);

	/* pin program and map */
	ret_pin_prog = bpf_obj_pin(progfd, prog_path);
	if (ret_pin_prog != 0)
		fprintf(stderr, "Error pinning program: %s\n", strerror(errno));

	ret_pin_map = bpf_obj_pin(mapfd, map_path);
	if (ret_pin_map != 0) {
		fprintf(stderr, "Error pinning map: %s\n", strerror(errno));
		if (ret_pin_prog == 0) {	/* if pinned program but not map, unpin program */
			if (unlink(prog_path) < 0)
				fprintf(stderr, "Error unpinning program: %s\n", strerror(errno));
		}
	}

	/* if error pinning program or map, detach program */
	if (ret_pin_prog != 0 || ret_pin_map != 0) {
		if (bpf_prog_detach2(progfd, devfd, BPF_BIO_SUBMIT))
			fprintf(stderr, "Error: failed to detach program\n");
		close(devfd);
		return 1;
	}

	close(devfd);
	printf("Pinned program to %s.\n", prog_path);
	printf("Pinned map to %s.\n", map_path);
	return 0;
}

static int detach(char *dev, char *pin_path)
{
	int ret, unlink_err, devfd, mapfd, progfd;
	char prog_path[256];
	char map_path[256];

	strcpy(prog_path, "/sys/fs/bpf/");
	strcat(prog_path, pin_path);

	strcpy(map_path, prog_path);
	strcat(map_path, "_map");

	progfd = bpf_obj_get(prog_path);
	mapfd = bpf_obj_get(map_path);
	if (progfd < 0 || mapfd < 0) {
		fprintf(stderr, "Error: failed to get pinned object\n");
		return 1;
	}

	devfd = open(dev, O_RDONLY);
	if (devfd == -1) {
		fprintf(stderr, "Error: failed to open block device %s\n", dev);
		return 1;
	}

	ret = bpf_prog_detach2(progfd, devfd, BPF_BIO_SUBMIT);
	if (ret) {
		fprintf(stderr, "Error: failed to detach program\n");
		close(devfd);
		return 1;
	}

	close(devfd);

	printf("Detached bpf io_filter_map program from device %s.\n", dev);

	unlink_err = 0;
	ret = unlink(prog_path);
	if (ret < 0) {
		fprintf(stderr, "Error unpinning program: %s\n", strerror(errno));
		unlink_err = 1;
	}

	ret = unlink(map_path);
	if (ret < 0) {
		fprintf(stderr, "Error unpinning map: %s\n", strerror(errno));
		unlink_err = 1;
	}

	return unlink_err;
}

static int update(char *pin_path, uint8_t op, uint32_t start, uint32_t count)
{
	int mapfd;
	char map_path[256];
	uint32_t index, val, sector, pos, ret;

	strcpy(map_path, "/sys/fs/bpf/");
	strcat(map_path, pin_path);
	strcat(map_path, "_map");

	mapfd = bpf_obj_get(map_path);
	if (mapfd < 0) {
		fprintf(stderr, "Error: failed to get pinned map\n");
		return 1;
	}

	sector = start;
	for (int i = 0; i < count; i++, sector++) {
		/* get map element */
		index = sector/32;
		pos = sector%32;

		ret = bpf_map_lookup_elem(mapfd, &index, &val);
		if (ret) {
			fprintf(stderr, "Error: unable to update map element at index %d\n", index);
			return 1;
		}

		/* could be more efficient if all bits for sectors evaluating to
		 * same index were set at same time, would eliminate extra calls
		 * to bpf_map_lookup/update_elem()
		 */
		if (op == IO_ALLOW)
			val &= ~(1 << pos); /* set bit to 0 */
		else
			val |= (1 << pos); /* set bit to 1 */

		/* update map element */
		ret = bpf_map_update_elem(mapfd, &index, &val, BPF_ANY);
		if (ret) {
			fprintf(stderr, "Error: unable to update map element at index %d\n", index);
			return 1;
		}
	}

	printf("Updated map values.\n");
	return 0;
}

static void usage(char *exec)
{
	printf("Functionality:\n");
	printf("\tAttach: load program and attach io filter to device\n");
	printf("\t\tpin program and map to a given destination\n");
	printf("\tUpdate: update map used to control which regions of io are filtered\n");
	printf("\tDetach: detach program from device\n");
	printf("\t\tunpin program and map\n");
	printf("Usage:\n");
	printf("\t%s <device> <prog name> --attach\n", exec);
	printf("\t%s <device> <prog name> --detach\n", exec);
	printf("\t%s <device> <prog name> --update <allow/block> <start sector> <sector count>\n", exec);
}

int main(int argc, char **argv)
{
	uint8_t mode, op;
	uint32_t start, count;

	if (argc < 4) {
		fprintf(stderr, "Error: too few arguments\n");
		usage(argv[0]);
		return 1;
	}

	if (strcmp(argv[3],  "--attach") == 0)
		mode = ATTACH;
	else if (strcmp(argv[3], "--update") == 0)
		mode = UPDATE;
	else if (strcmp(argv[3], "--detach") == 0)
		mode = DETACH;
	else {
		fprintf(stderr, "Error: invalid flag\n");
		usage(argv[0]);
		return 1;
	}

	if (mode != UPDATE && argc > 4) {
		fprintf(stderr, "Error: too many arguments\n");
		usage(argv[0]);
		return 1;
	}

	if (mode == UPDATE && argc != 7) {
		fprintf(stderr, "Error: invalid number of arguments\n");
		usage(argv[0]);
		return 1;
	}

	if (mode == ATTACH)
		return attach(argv[1], argv[2]);
	else if (mode == DETACH)
		return detach(argv[1], argv[2]);
	else if (mode == UPDATE) {
		if (strcmp(argv[4], "block") == 0)
			op = IO_BLOCK;
		else if (strcmp(argv[4], "allow") == 0)
			op = IO_ALLOW;
		else {
			fprintf(stderr, "Error: invalid update operation\n");
			usage(argv[0]);
			return 1;
		}

		start = atoi(argv[5]);
		if (start < 0) {
			fprintf(stderr, "Error: starting sector cannot be less than 0\n");
			return 1;
		}

		count = atoi(argv[6]);
		if (count <= 0) {
			fprintf(stderr, "Error: number of sectors must be greater than 0\n");
			return 1;
		}

		return update(argv[2], op, start, count);
	}

	return 1;
}
