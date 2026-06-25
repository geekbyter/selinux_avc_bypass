# SELinux AVC Bypass KPM

KPM (KernelPatch Module) that filters suspicious AVC audit records at the kernel level
to bypass Duck Detector's "enforcing with audit exposure" detection.

Author: geekbyte

This directory supersedes `../audit_bypass_kpm`. The old directory used the same
kernel `audit_log_end()` filtering logic under the `audit_exposure_bypass` name;
the maintained module name is now `selinux_avc_bypass`.

## How It Works

Duck Detector reads `logcat -b events -s auditd:I` and checks for AVC records containing
root tool signatures (su, magisk, /data/adb, etc.). This KPM hooks the kernel's
`audit_log_end()` function to intercept AVC audit records before they reach logd's
netlink socket, suppressing records that contain suspicious keywords.

This approach is superior to userspace hooking because:
- Filters at the source (kernel audit subsystem)
- Affects both logcat AND libselinux audit callback paths
- No process injection required
- Invisible to detection tools

## Detection Vectors Bypassed

| Detection Layer | How Bypassed |
|----------------|--------------|
| Logcat events buffer | AVC records never reach logd |
| Native JNI audit callback | libselinux callback never receives suspicious records |
| AVC side-channel | No matching records in logcat vs native probe |

## Filtered Keywords

### Process names (comm field)
- su, magisk, magiskd, ksud, kernelsu, apatch, apd

### Path tokens
- /su, /magisk, /data/adb, magiskd, ksud, kernelsu, apatch

## Build

### Build Requirements

- Android NDK with aarch64 clang.
- KernelPatch SDK source tree.
- Linux/WSL/GitHub Actions build environment with `make`, `curl` or `wget`, and
  standard shell utilities.

### GitHub Actions (Recommended)

Push this directory as a repository root for the simplest setup. If you keep it
as `selinux_avc_bypass` inside a larger repository, copy
`.github/workflows/main.yml` to the repository root `.github/workflows/`
directory; GitHub only discovers workflows from the repository root. The YAML
itself supports both project layouts, downloads KernelPatch `0.11.2`, installs
Android NDK `29.0.14206865`, and uploads `selinux_avc_bypass_1.0.0.kpm` as an
artifact.

### Local Build

```bash
# Clone the repository
git clone https://github.com/yourname/selinux_avc_bypass.git
cd selinux_avc_bypass

# Download KernelPatch SDK
wget -q "https://github.com/bmax121/KernelPatch/archive/refs/tags/0.11.2.tar.gz" -O kp.tar.gz
mkdir -p KernelPatch
tar xzf kp.tar.gz --strip-components=1 -C KernelPatch
rm kp.tar.gz

# Set NDK path
export ANDROID_NDK_HOME=/path/to/ndk

# Optional: use an existing KernelPatch checkout instead of ./KernelPatch
# export KP_DIR=/path/to/KernelPatch

# Build
make
```

Output: `selinux_avc_bypass_1.0.0.kpm`

## Install

```bash
# Load via KernelPatch
kpm load selinux_avc_bypass_1.0.0.kpm

# Check status
kpm ctl selinux_avc_bypass status
```

## Kernel Compatibility

- GKI 5.15+ (kernel >= 5.14): Full support (primary target)
- GKI 5.10 (kernel 5.10-5.13): Compatible with runtime struct detection
- Older kernels: May need struct offset adjustment

## Version

1.0.0
