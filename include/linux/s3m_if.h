/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Intel S3M Bridge Interface: Interface specification for the Secure Startup Services Module (S3M).
 * Copyright (c) 2024, Intel Corporation.
 *
 * Author: Will Skrydlak <will.j.skrydlak@linux.intel.com>
 */

#ifndef __S3M_IF_H
#define __S3M_IF_H

#include <linux/types.h>
#include <linux/ioctl.h>

#define S3M_MB_CMD_DISC BIT(0)
#define S3M_MB_CMD_SOCKET_ID BIT(8)
#define S3M_MB_MAX_PAYLOAD 1022
#define S3M_SOCKET_ID(ID) ((ID) & 0xFF)

/**
 * struct s3m_if_cmd - Define S3M command to be processed
 * @req_len:		The size of the request command (in DWORDs).
 * @resp_len:		The total size allocated for @payload (in DWORDs). Size must be large enough
 *			to contain the response from the S3M. If not enough space is allocated, the
 *			driver will return an error. The value of @resp_len must be >= @req_len.
 * @payload:		Contains the command bytes to be processed by S3M
 *
 * This structure is used to pass commands and receive response messages to/from the S3M via IOCTL
 * S3M_IF_SEND_DOE.
 */
struct s3m_if_cmd {
	__u32 req_len;
	__u32 resp_len;
	__u32 payload[] __counted_by(resp_len);
};

#define S3M_IF_MAGIC		0xFB
#define S3M_IF_SEND_DOE		_IOWR(S3M_IF_MAGIC, 0, struct s3m_if_cmd *)
#endif
