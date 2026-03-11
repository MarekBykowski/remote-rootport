#ifndef _LINUX_AVERY_DOE_H
#define _LINUX_AVERY_DOE_H

#include <linux/types.h>

struct avery_pci_config_op {
	__u32 type;
	__u32 offset;
	__u32 value;
	__s32 status;
} __attribute__((packed));

int avery_doe_submit_request(struct avery_pci_config_op *op);
int avery_doe_netlink_submit_request(struct avery_pci_config_op *op);

#endif
