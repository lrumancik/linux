#include <linux/bpf.h>
#include "bpf/bpf_helpers.h"
#include <linux/bio.h>

char _license[] SEC("license") = "GPL";

//TODO: update max entries to number of entries needed to cover all sectors
//	32 sectors per entry
//	could also group sectors by region and provide locking at region level
struct bpf_map_def SEC("maps") control = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 65535,
};

/* filters write operations (based on starting sector only) */
SEC("io_filter")
int filter_io(struct bpf_io_request *io_req)
{
	uint32_t region;
	uint32_t *val = NULL;
	uint32_t index, pos, flag;

	index = (uint32_t) io_req->sector_start / 32;	/* index into array control */
	pos = (uint32_t) io_req->sector_start % 32;	/* position of bit in control[index] */

	flag = 1;		// flag = 0000.....00001
	flag = flag << pos;	// flag = 0000...010...000   (shifted k positions)

	val = bpf_map_lookup_elem(&control, &index);

	//TODO: to check all sectors involved, add loop over entirety of io_req
	if (val && *(val) & flag && op_is_write(io_req->opf & REQ_OP_MASK))
		return IO_BLOCK;

	return IO_ALLOW;
}

