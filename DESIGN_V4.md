# v4.1.2 design: offset-free AVC suppression plus stale-buffer cleanup

## Goal

Stop canonical SELinux AVC records from reaching Android's events log, and
remove AVC records that were already written before a late KPM load, without
binding the KPM to a specific 5.10.236 kernel layout.

## Options considered

1. Keep hooking `audit_log_end` and correct the `audit_buffer`/`sk_buff`
   offsets. Rejected because private layouts vary with kernel source and
   configuration; writing `skb->len = 0` is also invalid for the following
   netlink length calculation.
2. Hook `audit_log_end` and dynamically resolve skb helper functions. Safer
   than offsets, but still requires parsing and mutating a partially built
   netlink skb and has more failure modes.
3. Hook `audit_log_start(ctx, gfp_mask, type)` and return `NULL` for
   `type == AUDIT_AVC`. Chosen because the function ABI and audit type are
   stable, callers already handle a `NULL` audit buffer, and no private data
   structures are accessed.
4. Attempt a best-effort KPM helper clear through `/system/bin/logcat -b
   events -c`. Chosen only as an opportunistic helper because logd does not
   expose per-line deletion, and touching logd/kernel-private buffers would be
   less portable.
5. Resolve `call_usermodehelper` at runtime instead of importing
   `kf_call_usermodehelper`. Chosen after the target runtime rejected a hard
   helper import during KPM load.
6. Use a boot service module for reliable stale-buffer cleanup: load KPM in
   `post-fs-data.sh`, then clear `events` from a normal root shell in
   `service.sh` after logd is available.

## Safety and compatibility boundaries

- Resolve `audit_log_start` at load time; fail module loading if absent.
- Use `hook_wrap3` and pair it with `hook_unwrap`.
- Suppress only audit record type 1400; leave every other audit type alone.
- Invoke only `/system/bin/logcat -b events -c`, never `logcat -b all -c`.
- Keep `call_usermodehelper` optional; failure to resolve it must not prevent
  the KPM from loading.
- Run any stale-buffer clear after the hook is active, so new AVC records
  cannot race into the buffer during cleanup.
- Treat clear failure as non-fatal; suppression still works for future AVCs.
- Provide `enable`, `disable`, `status`, `reset`, `clear`, and
  `enable-clear` controls.

## Known tradeoff

All SELinux AVC diagnostics are unavailable while suppression is enabled, and
the load-time cleanup clears the entire Android `events` buffer. Use
`disable` during policy debugging or unload the module.
