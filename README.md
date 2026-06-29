# SELinux AVC Bypass KPM v4.1.2

This KernelPatch module suppresses kernel audit records whose type is
`AUDIT_AVC` (1400). It is intended for controlled testing on the owner's
Android device.



----

# test this mudules + kpm file


## before:
<img width="480" height="1070" alt="image" src="https://github.com/user-attachments/assets/3da7268d-7f41-4bda-b2ab-0dae70d6c4b4" />


## flash this mudules  `selinux_avc_bypass_autoload.zip`

<img width="475" height="1001" alt="image" src="https://github.com/user-attachments/assets/d37682af-1d00-4fbd-a148-6db7875f0573" />



`selinux_avc_bypass_autoload.zip` has already automatically loaded the kpm file, so you do not need to manually load `selinux_avc_bypass.kpm`.


`selinux avc bypass_autoload.zip` automatically clears old AVC logs and loads `selinux avc bypass.kpm`, while `selinux avc bypass.kpm` handles the clearing of subsequently generated AVC logs.

## after:

<img width="460" height="760" alt="image" src="https://github.com/user-attachments/assets/52384d2e-fbed-485a-93a1-71e2415f6ac0" />

<img width="485" height="709" alt="image" src="https://github.com/user-attachments/assets/d7c51c11-828f-4a65-a4cd-d365b3945038" />

<img width="443" height="1040" alt="image" src="https://github.com/user-attachments/assets/b7c28971-cded-406f-8d45-61e7206f0b98" />


----


## v4.1.2 architecture

v4 hooks:

```c
audit_log_start(struct audit_context *ctx, gfp_t gfp_mask, int type)
```

When `type == 1400`, the hook skips record allocation and returns `NULL`.
Kernel callers already handle this normal result.

v4.1.2 also runs one best-effort helper clear of Android's `events` log buffer
after the hook is installed:

```text
/system/bin/logcat -b events -c
```

This is intentionally only a helper attempt. On the tested Redmi Note 11T Pro,
a kernel-spawned `logcat` returned success but did not actually clear logd's
events buffer. Reliable stale-buffer cleanup is therefore handled by the
included boot service module, which runs `logcat -b events -c` from a normal
root shell after loading the KPM. It deliberately clears only the `events`
buffer rather than all Android log buffers.

`call_usermodehelper` is resolved at runtime with `kallsyms_lookup_name` so
the KPM does not require a KernelPatch-exported `kf_call_usermodehelper`
import.

Unlike v3, v4.1.2 does not:

- read `audit_buffer` through a guessed offset;
- read or modify private `sk_buff` fields;
- branch on kernel version;
- run `logcat -b all -c`;
- use `unhook()` to remove a `hook_wrap()` hook.

The result is not tied to Redmi Note 11T Pro's 5.10.236 structure layout.
Loading fails cleanly if the target kernel does not expose
`audit_log_start`.

## Important tradeoff

While enabled, all SELinux AVC audit diagnostics are suppressed. Other audit
record types remain unchanged. Disable or unload the module when diagnosing
SELinux policy.

## Build

Requirements:

- Android NDK with aarch64 clang;
- KernelPatch SDK source tree.

```bash
export ANDROID_NDK_HOME=/path/to/ndk
export KP_DIR=/path/to/KernelPatch
make clean
make
```

Output:

```text
selinux_avc_bypass_4.1.2.kpm
```

The workspace Makefile also detects
`../_refs/selinux_hook/KernelPatch` when present.

## Install and verify

Exact KernelPatch CLI verbs differ by manager version. For the `ksud` CLI
used in this workspace:

```bash
ksud kpm load /data/local/tmp/selinux_avc_bypass_4.1.2.kpm
ksud kpm control selinux_avc_bypass status
```

Expected status contains:

```text
enabled=1 hook=1 type=1400 umh_clear=1/1 abi=audit_log_start/arg2 offset_free=1
```

On the tested SuKiSU/KernelPatch CLI, `ksud kpm control` prints only the
numeric return code (`0`) to stdout. The formatted status is available in
`dmesg` under `[selinux_avc_bypass] ctl:`.

The KPM helper attempts to clear the existing `events` buffer once after
loading. If you intentionally unload the module, trigger Duck Detector, and
reload while testing, you can force the same synchronous helper attempt:

```bash
ksud kpm control selinux_avc_bypass clear
```

For reliable cleanup on this device, use the included autoload module:

```text
autoload_module/
  module.prop
  post-fs-data.sh  # load KPM as early as possible
  service.sh       # confirm load and clear events from root shell
```

The root-shell clear is required for late-load verification because a kernel
hook can only stop new records; it cannot remove records already held by logd.

Then trigger a known denied SELinux access and verify:

```bash
logcat -d -b events -v brief -s auditd:I '*:S' -t 120
```

No new canonical `type=1400 ... avc: denied ...` line should appear, and the
module's `suppressed` counter should increase.

## Controls

```text
status   show hook state and counters
enable   suppress AUDIT_AVC records
disable  restore AVC auditing without unloading
reset    reset counters
clear    synchronously run the best-effort UMH events-clear helper
enable-clear  enable suppression and run the UMH events-clear helper
```

## Compatibility boundary

The module depends only on:

- runtime symbol lookup for `audit_log_start`;
- its stable three-argument calling convention;
- the stable UAPI audit type value 1400;
- runtime lookup of `call_usermodehelper` for optional stale-buffer cleanup;
- Android's public `/system/bin/logcat -b events -c` command for stale-buffer
  cleanup;
- KernelPatch's `hook_wrap3`/`hook_unwrap` API.

It contains no special case for kernel 5.10.236.
