#include <linux/bpf.h>
#include "bpf/bpf_helpers.h"
#include <linux/bio.h>

char _license[] SEC("license") = "GPL";

//TODO: update max entries to number of entries needed to cover all regions (32
//regions per entry)
struct bpf_map_def SEC("maps") control = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 65535,
};


SEC("kprobe/submit_bio")
int kprobe_submit_bio(struct pt_regs *ctx)
{
	uint32_t sectors_per_region = 256*1024*1024/512; // evaluates to 524288
	uint64_t sector = 1;
	uint32_t region;
	uint32_t *val = NULL;
	uint32_t index, pos, flag;
	struct bio *bio = (struct bio *)ctx->di;

	// Always use probe_read to read data from the kernel
	bpf_probe_read(&sector, sizeof(bio->bi_iter.bi_sector),
		       &bio->bi_iter.bi_sector);

	region = sector/sectors_per_region;
	index = region/32;  // gives the corresponding index in the array A
	pos = region%32;  // gives the corresponding bit position in A[i]
	flag = 1;  // flag = 0000.....00001
	flag = flag << pos;  // flag = 0000...010...000   (shifted k positions)
	val = bpf_map_lookup_elem(&control, &index);

	if (val && *val != 0)
	{
		if (*(val) & flag)
			bpf_printk("Found a sector where IO should actually fail. \n", 50);
	}
	if (val && ! (*(val) & flag))
		bpf_printk("Found sector where IO should SUCCEED\n", 50);


	return 0;
}

