/*
 * selinux_avc_bypass.h — AVC audit filter definitions
 *
 * Kernel AVC record filtering for bypassing Duck Detector's
 * "enforcing with audit exposure" detection.
 */

#ifndef __SELINUX_AVC_BYPASS_H
#define __SELINUX_AVC_BYPASS_H

#include <linux/kernel.h>

/* AVC payload scan limits */
#define AVC_PAYLOAD_COPY_SIZE   384

/* audit_buffer struct offsets (GKI 5.10+) */
#define AB_SKB_OFFSET_515       24   /* kernel >= 5.14: list(16) + ctx(8) */
#define AB_SKB_OFFSET_510       8    /* kernel < 5.14:  list(16) */

/* sk_buff field offsets (GKI arm64) */
#define SKB_LEN_OFFSET          108  /* unsigned int len */
#define SKB_DATA_OFFSET         208  /* unsigned char *data */

/* Detection keywords — must match Duck Detector's SUSPICIOUS_COMM_VALUES and
 * SUSPICIOUS_PATH_TOKENS exactly for complete coverage. */
#define AVC_KW_SU               "su"
#define AVC_KW_MAGISK           "magisk"
#define AVC_KW_MAGISKD          "magiskd"
#define AVC_KW_KSUD             "ksud"
#define AVC_KW_KERNELSU         "kernelsu"
#define AVC_KW_APATCH           "apatch"
#define AVC_KW_APD              "apd"
#define AVC_KW_DATA_ADB         "/data/adb"

/* Max hooks the module supports */
#define SELINUX_AVC_BYPASS_MAX_HOOKS  8

#endif /* __SELINUX_AVC_BYPASS_H */
