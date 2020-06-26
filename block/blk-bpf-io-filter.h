/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _BLK_BPF_IO_FILTER
#define _BLK_BPF_IO_FILTER

#ifdef CONFIG_BPF_IO_FILTER
void io_filter_bpf_init(struct gendisk *disk);
void io_filter_bpf_free(struct gendisk *disk);
int io_filter_bpf_run(struct bio *bio);
#else
static inline void io_filter_bpf_init(struct gendisk *disk) { }
static inline void io_filter_bpf_free(struct gendisk *disk) { }
static inline int io_filter_bpf_run(struct bio *bio) { return IO_ALLOW; }
#endif

#endif	/* _BLK_BPF_IO_FILTER */
