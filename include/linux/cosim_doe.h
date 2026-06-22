#ifndef _LINUX_COSIM_DOE_H
#define _LINUX_COSIM_DOE_H

#include <linux/types.h>

struct cosim_pci_config_op {
	__u32 type;
	__u32 offset;
	__u32 value;
	__s32 status;
} __attribute__((packed));

int cosim_doe_submit_request(struct cosim_pci_config_op *op);
int cosim_doe_netlink_submit_request(struct cosim_pci_config_op *op);

#endif
