/*
 * selinux_avc_bypass.h - stable audit hook contract
 *
 * This module deliberately avoids private audit_buffer and sk_buff layouts.
 */

#ifndef __SELINUX_AVC_BYPASS_H
#define __SELINUX_AVC_BYPASS_H

/* Linux uapi/linux/audit.h: AUDIT_AVC has been 1400 for supported kernels. */
#define SELINUX_AVC_AUDIT_TYPE 1400U

#define SELINUX_AVC_BYPASS_STATUS_SIZE 320U

#endif /* __SELINUX_AVC_BYPASS_H */
