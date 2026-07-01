#ifndef _LINUX_COSIM_ENUM_H
#define _LINUX_COSIM_ENUM_H

#include <linux/types.h>

struct cosim_pci_enum_op {
	__u32 type;
	__u32 bus;
	__u32 devfn;
	__u32 offset;
	__u32 size;
	__u32 value;
	__s32 status;
} __attribute__((packed));

#define COSIM_ENUM_READ  0
#define COSIM_ENUM_WRITE 1

#endif
