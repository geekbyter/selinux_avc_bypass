#!/system/bin/sh

MODDIR="${0%/*}"
KPM="$MODDIR/selinux_avc_bypass.kpm"
KSUD="/data/adb/ksud"
LOG_BIN="/system/bin/log"
TAG="SelinuxAvcBypassBoot"

logi() {
    "$LOG_BIN" -t "$TAG" "$*" 2>/dev/null
}

load_kpm() {
    if [ ! -r "$KPM" ]; then
        logi "post-fs-data: missing KPM: $KPM"
        return 1
    fi

    if [ ! -x "$KSUD" ]; then
        KSUD="ksud"
    fi

    if "$KSUD" kpm list 2>/dev/null | grep -qx "selinux_avc_bypass"; then
        logi "post-fs-data: selinux_avc_bypass already loaded"
        return 0
    fi

    "$KSUD" kpm load "$KPM" >/dev/null 2>&1
    rc=$?
    logi "post-fs-data: kpm load rc=$rc"
    return "$rc"
}

load_kpm >/dev/null 2>&1
exit 0
