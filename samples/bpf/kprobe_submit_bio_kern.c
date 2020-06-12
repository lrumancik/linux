#include <linux/bpf.h>
#include "bpf/bpf_helpers.h"
#include <linux/bio.h>

char _license[] SEC("license") = "GPL";

SEC("kprobe/submit_bio")
int kprobe_submit_bio(struct pt_regs *ctx)
{
	return 0;
}

