#!/system/bin/sh

MODDIR="${0%/*}"
KPM="$MODDIR/selinux_avc_bypass.kpm"
KSUD="/data/adb/ksud"
LOGCAT_BIN="/system/bin/logcat"
LOG_BIN="/system/bin/log"
TAG="SelinuxAvcBypassBoot"

logi() {
    "$LOG_BIN" -t "$TAG" "$*" 2>/dev/null
}

ensure_kpm_loaded() {
    if [ ! -r "$KPM" ]; then
        logi "service: missing KPM: $KPM"
        return 1
    fi

    if [ ! -x "$KSUD" ]; then
        KSUD="ksud"
    fi

    if "$KSUD" kpm list 2>/dev/null | grep -qx "selinux_avc_bypass"; then
        logi "service: selinux_avc_bypass already loaded"
        return 0
    fi

    "$KSUD" kpm load "$KPM" >/dev/null 2>&1
    rc=$?
    logi "service: kpm load rc=$rc"
    return "$rc"
}

clear_events() {
    "$LOGCAT_BIN" -b events -c >/dev/null 2>&1
    rc=$?
    logi "service: logcat events clear rc=$rc"
    return "$rc"
}

ensure_kpm_loaded >/dev/null 2>&1

# Clear after the hook is active.  Repeating with short gaps handles the
# normal boot window where logd may become ready slightly after service start.
clear_events >/dev/null 2>&1
sleep 2
clear_events >/dev/null 2>&1
sleep 5
clear_events >/dev/null 2>&1

"$KSUD" kpm control selinux_avc_bypass status >/dev/null 2>&1
exit 0
