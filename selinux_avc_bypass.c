/*
 * selinux_avc_bypass.c — KPM module to filter suspicious AVC audit records
 *
 * Hooks kernel's audit_log_end() to intercept AVC audit records before they
 * reach logd's netlink socket. Suppresses records containing root tool
 * signatures (su, magisk, /data/adb, etc.) to bypass Duck Detector's
 * "enforcing with audit exposure" detection.
 *
 * Detection vectors bypassed:
 *   1. logcat -b events -s auditd:I  (AVC records never reach logd)
 *   2. libselinux avc_audit_callback (callback never fires for filtered records)
 *   3. AVC side-channel correlation   (no records to correlate)
 *
 * Copyright (C) 2024 geekbyte. SPDX-License-Identifier: GPL-3.0
 */

#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/err.h>
#include <asm/current.h>
#include <asm-generic/rwonce.h>
#include <uapi/asm-generic/errno.h>
#include <ksyms.h>
#include <hook.h>
#include <kpmodule.h>
#include <kputils.h>

#ifndef SELINUX_AVC_BYPASS_VERSION
#define SELINUX_AVC_BYPASS_VERSION "1.0.0"
#endif

KPM_NAME("selinux_avc_bypass");
KPM_VERSION(SELINUX_AVC_BYPASS_VERSION);
KPM_LICENSE("GPLv3");
KPM_AUTHOR("geekbyte");
KPM_DESCRIPTION("Kernel AVC audit filter — bypasses Duck Detector audit exposure check");

/* ================================================================
 * audit_buffer struct layout
 *
 * The kernel's audit_buffer contains an skb pointer we need to reach.
 * Layout varies by kernel version:
 *
 *   GKI 5.10  (kernel < 5.14):
 *     list_head(16) | skb(8) | gfp_mask(4)
 *     skb at offset 8
 *
 *   GKI 5.15+ (kernel >= 5.14):
 *     list_head(16) | ctx(8) | skb(8) | gfp_mask(4)
 *     skb at offset 24
 * ================================================================ */
struct sk_buff;

#define AB_SKB_OFFSET_515  24
#define AB_SKB_OFFSET_510  8

/* ================================================================
 * AVC filter keywords
 *
 * Exact match with Duck Detector's detection lists:
 *   SUSPICIOUS_COMM_VALUES = {su, magisk, magiskd, ksud, kernelsu, apatch, apd}
 *   SUSPICIOUS_PATH_TOKENS = {/su, /magisk, /data/adb, magiskd, ksud, kernelsu, apatch}
 * ================================================================ */
static const char *g_avc_keywords[] = {
    "su",         /* comm="su", path with /su */
    "magisk",     /* comm="magisk"/"magiskd", path /magisk */
    "magiskd",    /* comm="magiskd" */
    "ksud",       /* comm="ksud" (KernelSU) */
    "kernelsu",   /* comm="kernelsu" */
    "apatch",     /* comm="apatch" */
    "apd",        /* comm="apd" (Apatch) */
    "/data/adb",  /* path="/data/adb/..." */
    NULL
};

#define AVC_PAYLOAD_COPY_SIZE  384

/* ================================================================
 * Globals
 * ================================================================ */
static long (*g_copy_from_kernel_nofault)(void *dst, const void *src, size_t size);
static void (*g_audit_log_end)(void *ab);
static int g_num_hooks;
static void *g_hook_addrs[8];

static unsigned int g_skb_offset = AB_SKB_OFFSET_515;
static bool g_struct_verified;

static u32 g_total_calls;
static u32 g_filtered_records;
static u32 g_avc_records_seen;

/* ================================================================
 * Helpers
 * ================================================================ */
static const char *cur_comm(void)
{
    if (task_struct_offset.comm_offset <= 0)
        return "?";
    return get_task_comm(current) ?: "?";
}

static bool str_eq(const char *a, const char *b)
{
    if (!a || !b) return false;
    while (*a && *a == *b) { a++; b++; }
    return *a == *b;
}

static bool is_policy_manager(void)
{
    const char *c = cur_comm();
    return str_eq(c, "magiskpolicy") ||
           str_eq(c, "apd") ||
           str_eq(c, "truncate");
}

static bool char_lower_eq(char a, char b)
{
    if (a >= 'A' && a <= 'Z') a += 32;
    if (b >= 'A' && b <= 'Z') b += 32;
    return a == b;
}

static bool contains_ci(const char *buf, size_t buf_len,
                         const char *needle, size_t needle_len)
{
    size_t i, j;

    if (!buf || !needle || !needle_len || buf_len < needle_len)
        return false;

    for (i = 0; i + needle_len <= buf_len; i++) {
        for (j = 0; j < needle_len; j++) {
            if (!char_lower_eq(buf[i + j], needle[j]))
                break;
        }
        if (j == needle_len)
            return true;
    }
    return false;
}

static size_t slen(const char *s)
{
    size_t n = 0;
    if (s) while (s[n]) n++;
    return n;
}

/* ================================================================
 * sk_buff field access (direct offsets for GKI 5.10+ arm64)
 *
 * These avoid including the massive sk_buff header chain.
 * Verified against android-gki kernel source.
 * ================================================================ */
#define SKB_LEN_OFFSET   108  /* unsigned int len */
#define SKB_DATA_OFFSET  208  /* unsigned char *data */

static struct sk_buff *ab_get_skb(void *ab)
{
    struct sk_buff *skb = NULL;

    if (!ab || !g_copy_from_kernel_nofault)
        return NULL;

    if (g_copy_from_kernel_nofault(&skb,
            (const char *)ab + g_skb_offset, sizeof(skb)) != 0)
        return NULL;

    return skb;
}

static bool skb_get_payload(struct sk_buff *skb, unsigned char **data_out,
                             unsigned int *len_out)
{
    unsigned char *data = NULL;
    unsigned int len = 0;

    if (!skb || !g_copy_from_kernel_nofault)
        return false;

    if (g_copy_from_kernel_nofault(&len,
            (const char *)skb + SKB_LEN_OFFSET, sizeof(len)) != 0)
        return false;

    if (g_copy_from_kernel_nofault(&data,
            (const char *)skb + SKB_DATA_OFFSET, sizeof(data)) != 0)
        return false;

    if (!data || len == 0 || len > 4096)
        return false;

    *data_out = data;
    *len_out = len;
    return true;
}

/* ================================================================
 * AVC record detection
 *
 * AVC format:
 *   type=1400 audit(...): avc: denied { read } for pid=...
 *     comm="magiskd" path="/data/adb/modules" ...
 *     scontext=u:r:magisk:s0 tcontext=u:object_r:adb_data_file:s0
 *     tclass=dir permissive=0
 * ================================================================ */
static bool is_avc_record(const char *buf, size_t len)
{
    return contains_ci(buf, len, "avc:", 4) &&
           (contains_ci(buf, len, "denied", 6) ||
            contains_ci(buf, len, "granted", 7));
}

static bool has_suspicious_keyword(const char *buf, size_t len)
{
    int i;

    for (i = 0; g_avc_keywords[i]; i++) {
        if (contains_ci(buf, len, g_avc_keywords[i], slen(g_avc_keywords[i])))
            return true;
    }
    return false;
}

static bool should_filter_audit_record(void *ab)
{
    struct sk_buff *skb;
    unsigned char *data = NULL;
    unsigned int len = 0;
    unsigned char payload[AVC_PAYLOAD_COPY_SIZE];
    size_t copy_len;

    skb = ab_get_skb(ab);
    if (!skb)
        return false;

    if (!skb_get_payload(skb, &data, &len) || len == 0)
        return false;

    copy_len = len;
    if (copy_len > AVC_PAYLOAD_COPY_SIZE - 1)
        copy_len = AVC_PAYLOAD_COPY_SIZE - 1;

    if (g_copy_from_kernel_nofault &&
        g_copy_from_kernel_nofault(payload, data, copy_len) != 0)
        return false;

    payload[copy_len] = '\0';

    if (!is_avc_record((const char *)payload, copy_len))
        return false;

    g_avc_records_seen++;

    if (!has_suspicious_keyword((const char *)payload, copy_len))
        return false;

    return true;
}

/* ================================================================
 * audit_log_end hook
 *
 * Zero skb->len before the original function dispatches the record.
 * audit_log_end() → audit_log_common_recv_msg() sends an empty
 * netlink control message (type=1130) that logd ignores.
 * The original function still frees the audit_buffer properly.
 * ================================================================ */
static void before_audit_log_end(hook_fargs4_t *a, void *u)
{
    void *ab;
    struct sk_buff *skb;

    (void)u;

    WRITE_ONCE(g_total_calls, READ_ONCE(g_total_calls) + 1);

    if (is_policy_manager())
        return;

    ab = (void *)a->arg0;
    if (!ab)
        return;

    if (!should_filter_audit_record(ab))
        return;

    skb = ab_get_skb(ab);
    if (skb) {
        unsigned int *len_ptr = (unsigned int *)((const char *)skb + SKB_LEN_OFFSET);
        WRITE_ONCE(*len_ptr, 0);
    }

    WRITE_ONCE(g_filtered_records, READ_ONCE(g_filtered_records) + 1);
}

/* ================================================================
 * Struct layout detection (runtime)
 * ================================================================ */
static void detect_audit_buffer_layout(void)
{
    if (kver >= VERSION(5, 14, 0)) {
        g_skb_offset = AB_SKB_OFFSET_515;
        pr_info("[selinux_avc_bypass] kernel >= 5.14, skb offset = %u\n", g_skb_offset);
    } else {
        g_skb_offset = AB_SKB_OFFSET_510;
        pr_info("[selinux_avc_bypass] kernel < 5.14, skb offset = %u\n", g_skb_offset);
    }
    g_struct_verified = true;
}

/* ================================================================
 * Symbol resolution
 * ================================================================ */
static void *resolve_symbol(const char *name, const char *fallback)
{
    void *addr = (void *)kallsyms_lookup_name(name);
    if (addr) {
        pr_info("[selinux_avc_bypass] %s @ %px\n", name, addr);
        return addr;
    }
    if (fallback) {
        addr = (void *)kallsyms_lookup_name(fallback);
        if (addr) {
            pr_info("[selinux_avc_bypass] %s (fallback for %s) @ %px\n", fallback, name, addr);
            return addr;
        }
    }
    pr_warn("[selinux_avc_bypass] cannot resolve %s\n", name);
    return NULL;
}

/* ================================================================
 * Control interface
 * ================================================================ */
static long control(const char *args, char __user *out_msg, int outlen)
{
    char buf[256];
    size_t args_len = 0;

    (void)outlen;

    if (args) {
        const char *p = args;
        while (*p) { args_len++; p++; }
    }

    if (contains_ci(args, args_len, "filter", 6)) {
        const char *test = "type=1400 audit(1234.567:890): avc: denied { read }"
            " for pid=1234 comm=\"magiskd\" path=\"/data/adb/modules\""
            " scontext=u:r:magisk:s0 tcontext=u:object_r:adb_data_file:s0"
            " tclass=dir permissive=0";
        bool r = has_suspicious_keyword(test, slen(test));
        sprintf(buf, "filter_test match=%d\n", r ? 1 : 0);
    } else if (contains_ci(args, args_len, "status", 6)) {
        sprintf(buf, "v%s hooks=%d total=%u filtered=%u avc=%u off=%u ok=%d\n",
                SELINUX_AVC_BYPASS_VERSION, g_num_hooks,
                READ_ONCE(g_total_calls), READ_ONCE(g_filtered_records),
                READ_ONCE(g_avc_records_seen), g_skb_offset,
                g_struct_verified ? 1 : 0);
    } else {
        sprintf(buf, "v%s loaded; use: status | filter\n", SELINUX_AVC_BYPASS_VERSION);
    }

    pr_info("[selinux_avc_bypass] ctl: %s\n", buf);

    if (out_msg)
        compat_copy_to_user(out_msg, buf, slen(buf) + 1);

    return 0;
}

/* ================================================================
 * Module init / exit
 * ================================================================ */
static long init(const char *args, const char *event, void *__user r)
{
    int rc;

    (void)args;
    (void)r;

    pr_info("[selinux_avc_bypass] init event=%s v%s\n",
            event ?: "(null)", SELINUX_AVC_BYPASS_VERSION);

    g_copy_from_kernel_nofault = resolve_symbol("copy_from_kernel_nofault",
                                                 "probe_kernel_read");
    if (!g_copy_from_kernel_nofault) {
        pr_err("[selinux_avc_bypass] FATAL: no copy_from_kernel_nofault\n");
        return -ENOENT;
    }

    detect_audit_buffer_layout();

    g_audit_log_end = resolve_symbol("audit_log_end", NULL);
    if (!g_audit_log_end) {
        pr_err("[selinux_avc_bypass] FATAL: no audit_log_end\n");
        return -ENOENT;
    }

    g_hook_addrs[g_num_hooks] = g_audit_log_end;
    rc = hook_wrap(g_audit_log_end, 1, before_audit_log_end, NULL, NULL);
    if (rc) {
        pr_err("[selinux_avc_bypass] hook audit_log_end failed: %d\n", rc);
        return -rc;
    }
    g_num_hooks++;

    pr_info("[selinux_avc_bypass] %d hook(s) installed — AVC filter active\n", g_num_hooks);
    pr_info("[selinux_avc_bypass] keywords: su, magisk, magiskd, ksud, kernelsu, apatch, apd, /data/adb\n");

    return 0;
}

static long exit_(void *__user r)
{
    int i;

    (void)r;

    for (i = 0; i < g_num_hooks; i++) {
        if (g_hook_addrs[i]) {
            unhook(g_hook_addrs[i]);
            pr_info("[selinux_avc_bypass] unhook [%d]\n", i);
        }
    }
    g_num_hooks = 0;

    pr_info("[selinux_avc_bypass] exit — total=%u filtered=%u avc=%u\n",
            READ_ONCE(g_total_calls),
            READ_ONCE(g_filtered_records),
            READ_ONCE(g_avc_records_seen));

    return 0;
}

KPM_INIT(init);
KPM_CTL0(control);
KPM_EXIT(exit_);
