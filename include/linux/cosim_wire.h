#ifndef _LINUX_COSIM_WIRE_H
#define _LINUX_COSIM_WIRE_H

#include <linux/types.h>
#include <linux/cosim_enum.h>
#include <linux/cosim_mmio.h>

enum cosim_op_kind {
	COSIM_OP_CFG  = 0,
	COSIM_OP_MMIO = 1,
};

struct cosim_wire_op {
	__u32 kind;
	union {
		struct cosim_pci_enum_op enum_op;
		struct cosim_pci_mmio_op mmio;
	};
};

#endif
