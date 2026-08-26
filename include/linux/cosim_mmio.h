#ifndef _LINUX_COSIM_MMIO_H
#define _LINUX_COSIM_MMIO_H

#include <linux/types.h>

struct cosim_pci_mmio_op {
	__u32 type;
	__u32 bus;
	__u32 devfn;
	__u64 addr;
	__u32 size;
	__u64 value;
	__s32 status;
} __attribute__((packed));

#define COSIM_MMIO_READ  0
#define COSIM_MMIO_WRITE 1

#endif
