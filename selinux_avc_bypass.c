/*
 * selinux_avc_bypass.c - suppress SELinux AVC audit record creation
 *
 * v4 hooks audit_log_start(ctx, gfp_mask, type) and returns NULL for
 * AUDIT_AVC (1400).  Callers already treat NULL as "auditing unavailable",
 * so no audit_buffer is allocated and no sk_buff needs to be inspected or
 * modified.
 *
 * Compatibility rule:
 *   - resolve audit_log_start by symbol at runtime;
 *   - use its long-standing three-argument ABI;
 *   - never depend on kernel-private structure offsets.
 *
 * v4.1.2 also makes one best-effort attempt to clear Android's events log
 * buffer after a successful hook install, and exposes a manual "clear"
 * control.  This helper path uses Android's public logcat command instead of
 * touching logd/kernel-private buffers.  call_usermodehelper is resolved at
 * runtime so this module can still load on KernelPatch builds that do not
 * export the helper as a KPM import.  On some Android builds, a kernel-spawned
 * logcat can exit with rc=0 without actually clearing logd; use a root-shell
 * boot service for reliable stale-buffer cleanup.
 *
 * While enabled, SELinux AVC diagnostics are intentionally unavailable.
 * Other audit record types are left untouched.
 *
 * SPDX-License-Identifier: GPL-3.0
 */

#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <asm-generic/rwonce.h>
#include <uapi/asm-generic/errno.h>
#include <ksyms.h>
#include <hook.h>
#include <kpmodule.h>
#include <kputils.h>

#include "selinux_avc_bypass.h"

#ifndef SELINUX_AVC_BYPASS_VERSION
#define SELINUX_AVC_BYPASS_VERSION "4.1.2"
#endif

#define SELINUX_AVC_UMH_WAIT_EXEC 0x01
#define SELINUX_AVC_UMH_WAIT_PROC 0x02

typedef int (*call_usermodehelper_fn_t)(const char *path, char **argv,
                                        char **envp, int wait);

KPM_NAME("selinux_avc_bypass");
KPM_VERSION(SELINUX_AVC_BYPASS_VERSION);
KPM_LICENSE("GPLv3");
KPM_AUTHOR("geekbyte");
KPM_DESCRIPTION("Offset-free AUDIT_AVC suppression with best-effort clear");

static void *g_audit_log_start;
static bool g_hook_installed;
static bool g_enabled = true;
static call_usermodehelper_fn_t g_call_usermodehelper;
static unsigned long g_audit_start_calls;
static unsigned long g_avc_suppressed;
static unsigned long g_umh_clear_attempts;
static unsigned long g_umh_clear_rc_ok;
static int g_last_umh_clear_rc;

static size_t local_strlen(const char *s)
{
    size_t n = 0;

    if (!s)
        return 0;

    while (s[n])
        n++;

    return n;
}

static bool command_is(const char *args, const char *expected)
{
    size_t i = 0;
    size_t expected_len = local_strlen(expected);

    if (!args || !expected)
        return false;

    while (*args == ' ' || *args == '\t')
        args++;

    while (i < expected_len && args[i] == expected[i])
        i++;

    if (i != expected_len)
        return false;

    while (args[i] == ' ' || args[i] == '\t' ||
           args[i] == '\r' || args[i] == '\n')
        i++;

    return args[i] == '\0';
}

static int clear_events_buffer(const char *reason, bool wait_for_exit)
{
    char *argv[] = {
        "/system/bin/logcat",
        "-b",
        "events",
        "-c",
        NULL,
    };
    char *envp[] = {
        "HOME=/",
        "PATH=/system/bin:/system_ext/bin:/product/bin:/vendor/bin:/sbin",
        "ANDROID_ROOT=/system",
        "ANDROID_DATA=/data",
        NULL,
    };
    int wait = wait_for_exit ? SELINUX_AVC_UMH_WAIT_PROC :
                               SELINUX_AVC_UMH_WAIT_EXEC;
    int rc;

    if (!g_call_usermodehelper) {
        g_call_usermodehelper =
            (call_usermodehelper_fn_t)
                kallsyms_lookup_name("call_usermodehelper");
    }

    WRITE_ONCE(g_umh_clear_attempts,
               READ_ONCE(g_umh_clear_attempts) + 1);

    if (!g_call_usermodehelper) {
        rc = -ENOENT;
        WRITE_ONCE(g_last_umh_clear_rc, rc);
        pr_warn("[selinux_avc_bypass] umh-clear-events unavailable: reason=%s "
                "call_usermodehelper not found\n",
                reason ? reason : "(null)");
        return rc;
    }

    rc = g_call_usermodehelper(argv[0], argv, envp, wait);
    WRITE_ONCE(g_last_umh_clear_rc, rc);

    if (rc == 0)
        WRITE_ONCE(g_umh_clear_rc_ok,
                   READ_ONCE(g_umh_clear_rc_ok) + 1);

    if (rc == 0) {
        pr_info("[selinux_avc_bypass] umh-clear-events rc-ok: reason=%s "
                "wait=%s\n",
                reason ? reason : "(null)",
                wait_for_exit ? "proc" : "exec");
    } else {
        pr_warn("[selinux_avc_bypass] umh-clear-events failed: reason=%s "
                "wait=%s rc=%d\n",
                reason ? reason : "(null)",
                wait_for_exit ? "proc" : "exec", rc);
    }

    return rc;
}

/*
 * audit_log_start(struct audit_context *ctx, gfp_t gfp_mask, int type)
 *
 * A NULL result is a documented/normal outcome.  audit_log_start itself
 * returns NULL when auditing is unavailable, and its callers already handle
 * that case.  Skipping before allocation avoids both leaks and private ABI
 * access.
 */
static void before_audit_log_start(hook_fargs3_t *a, void *udata)
{
    unsigned int type;

    (void)udata;

    WRITE_ONCE(g_audit_start_calls,
               READ_ONCE(g_audit_start_calls) + 1);

    if (!READ_ONCE(g_enabled))
        return;

    type = (unsigned int)a->arg2;
    if (type != SELINUX_AVC_AUDIT_TYPE)
        return;

    a->ret = 0;
    a->skip_origin = 1;

    WRITE_ONCE(g_avc_suppressed,
               READ_ONCE(g_avc_suppressed) + 1);
}

static void copy_status_to_user(char __user *out_msg, int outlen, char *buf)
{
    size_t copy_len;

    if (!out_msg || outlen <= 0)
        return;

    copy_len = local_strlen(buf) + 1;
    if (copy_len > (size_t)outlen) {
        copy_len = (size_t)outlen;
        buf[copy_len - 1] = '\0';
    }

    compat_copy_to_user(out_msg, buf, copy_len);
}

static long control(const char *args, char __user *out_msg, int outlen)
{
    char buf[SELINUX_AVC_BYPASS_STATUS_SIZE];
    int rc;

    if (command_is(args, "enable")) {
        WRITE_ONCE(g_enabled, true);
        snprintf(buf, sizeof(buf),
                 "enabled: AUDIT_AVC type=%u suppression active\n",
                 SELINUX_AVC_AUDIT_TYPE);
    } else if (command_is(args, "clear")) {
        rc = clear_events_buffer("control", true);
        snprintf(buf, sizeof(buf),
                 "umh clear-events rc=%d attempts=%lu rc_ok=%lu "
                 "(root-shell service may still be required)\n",
                 rc,
                 READ_ONCE(g_umh_clear_attempts),
                 READ_ONCE(g_umh_clear_rc_ok));
    } else if (command_is(args, "enable-clear")) {
        WRITE_ONCE(g_enabled, true);
        rc = clear_events_buffer("control-enable-clear", true);
        snprintf(buf, sizeof(buf),
                 "enabled; umh clear-events rc=%d attempts=%lu rc_ok=%lu\n",
                 rc,
                 READ_ONCE(g_umh_clear_attempts),
                 READ_ONCE(g_umh_clear_rc_ok));
    } else if (command_is(args, "disable")) {
        WRITE_ONCE(g_enabled, false);
        snprintf(buf, sizeof(buf),
                 "disabled: AVC auditing restored without unloading\n");
    } else if (command_is(args, "reset")) {
        WRITE_ONCE(g_audit_start_calls, 0);
        WRITE_ONCE(g_avc_suppressed, 0);
        snprintf(buf, sizeof(buf), "counters reset\n");
    } else if (!args || command_is(args, "") || command_is(args, "status")) {
        snprintf(buf, sizeof(buf),
                 "v%s enabled=%u hook=%u seen=%lu suppressed=%lu "
                 "type=%u umh_clear=%lu/%lu last_umh_rc=%d "
                 "abi=audit_log_start/arg2 offset_free=1\n",
                 SELINUX_AVC_BYPASS_VERSION,
                 READ_ONCE(g_enabled) ? 1U : 0U,
                 READ_ONCE(g_hook_installed) ? 1U : 0U,
                 READ_ONCE(g_audit_start_calls),
                 READ_ONCE(g_avc_suppressed),
                 SELINUX_AVC_AUDIT_TYPE,
                 READ_ONCE(g_umh_clear_rc_ok),
                 READ_ONCE(g_umh_clear_attempts),
                 READ_ONCE(g_last_umh_clear_rc));
    } else {
        snprintf(buf, sizeof(buf),
                 "unknown command; use status|enable|disable|reset|"
                 "clear|enable-clear\n");
    }

    pr_info("[selinux_avc_bypass] ctl: %s", buf);
    copy_status_to_user(out_msg, outlen, buf);
    return 0;
}

static long init(const char *args, const char *event, void *__user reserved)
{
    hook_err_t rc;

    (void)args;
    (void)reserved;

    pr_info("[selinux_avc_bypass] init event=%s v%s\n",
            event ? event : "(null)", SELINUX_AVC_BYPASS_VERSION);

    g_audit_log_start =
        (void *)kallsyms_lookup_name("audit_log_start");
    if (!g_audit_log_start) {
        pr_err("[selinux_avc_bypass] audit_log_start unavailable; "
               "refusing unsafe fallback\n");
        return -ENOENT;
    }

    rc = hook_wrap3(g_audit_log_start,
                    before_audit_log_start, NULL, NULL);
    if (rc != HOOK_NO_ERR) {
        pr_err("[selinux_avc_bypass] hook_wrap3 failed: %d\n", rc);
        g_audit_log_start = NULL;
        return -(long)rc;
    }

    WRITE_ONCE(g_hook_installed, true);
    WRITE_ONCE(g_enabled, true);

    pr_info("[selinux_avc_bypass] active: audit_log_start=%px "
            "AUDIT_AVC=%u, no private offsets\n",
            g_audit_log_start, SELINUX_AVC_AUDIT_TYPE);
    clear_events_buffer("init", false);
    pr_warn("[selinux_avc_bypass] AVC diagnostics are suppressed while enabled\n");
    return 0;
}

static long exit_(void *__user reserved)
{
    (void)reserved;

    WRITE_ONCE(g_enabled, false);

    if (READ_ONCE(g_hook_installed) && g_audit_log_start) {
        hook_unwrap(g_audit_log_start,
                    before_audit_log_start, NULL);
        WRITE_ONCE(g_hook_installed, false);
    }

    pr_info("[selinux_avc_bypass] exit: seen=%lu suppressed=%lu\n",
            READ_ONCE(g_audit_start_calls),
            READ_ONCE(g_avc_suppressed));

    g_audit_log_start = NULL;
    return 0;
}

KPM_INIT(init);
KPM_CTL0(control);
KPM_EXIT(exit_);
