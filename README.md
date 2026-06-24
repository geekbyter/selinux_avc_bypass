# SELinux AVC Bypass KPM

KPM (KernelPatch Module) that filters suspicious AVC audit records at the kernel level
to bypass Duck Detector's "enforcing with audit exposure" detection.

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

### GitHub Actions (Recommended)

Push to GitHub and the workflow will automatically download KernelPatch SDK and compile
the KPM module. Download the `.kpm` file from the Actions artifacts.

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
