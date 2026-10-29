#!/usr/bin/env bash
# ==============================================================================
# Mobile Device Security Inspector via Android Debug Bridge (ADB)
# Used to collect technical evidence for Section 4 (Mobile Audit) of PAI-3
# ==============================================================================

set -euo pipefail

OUT_DIR="evidence/mobile_audit_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUT_DIR"

echo "=========================================================="
echo " Mobile BYOD Security Audit Inspector (ADB)"
echo "=========================================================="

if ! command -v adb &>/dev/null; then
    echo "[!] adb is not found in PATH. Please verify Android SDK platform-tools."
    exit 1
fi

DEVICE_COUNT=$(adb devices | grep -v "List" | grep "device$" | wc -l)
if [ "$DEVICE_COUNT" -eq 0 ]; then
    echo "[!] No connected Android devices or emulators detected via ADB."
    echo "[i] Ensure USB debugging is enabled on the mobile device."
    exit 1
fi

echo "[+] Connected device detected. Gathering security configuration posture..."

# 1. Device and OS identification
echo "[*] Collecting system properties..."
adb shell getprop ro.build.version.release > "$OUT_DIR/android_version.txt"
adb shell getprop ro.build.version.security_patch > "$OUT_DIR/security_patch_level.txt"
adb shell getprop ro.product.model > "$OUT_DIR/device_model.txt"

# 2. Check Rooting / SELinux status
echo "[*] Verifying environment integrity (Root / SELinux)..."
adb shell getenforce > "$OUT_DIR/selinux_status.txt"
adb shell "which su 2>&1 || ls -l /system/xbin/su /system/bin/su /sbin/su 2>&1" > "$OUT_DIR/root_binary_check.txt"

# 3. Check Unknown Sources (Sideloading)
echo "[*] Checking unknown sources setting..."
adb shell settings get secure install_non_market_apps > "$OUT_DIR/unknown_sources_setting.txt"

# 4. Active network sockets (supervisión de conexiones en segundo plano)
echo "[*] Auditing active network sockets (TCP/UDP)..."
adb shell "netstat -tlpn 2>/dev/null || ss -tunap 2>/dev/null || cat /proc/net/tcp" > "$OUT_DIR/active_sockets.txt"

# 5. Inspect apps with Accessibility and Overlay permissions
echo "[*] Inspecting high-risk permissions (Accessibility / Overlays)..."
adb shell settings get secure enabled_accessibility_services > "$OUT_DIR/accessibility_services.txt"
adb shell cmd appops query-op SYSTEM_ALERT_WINDOW allow > "$OUT_DIR/screen_overlay_permissions.txt"

echo "=========================================================="
echo " Audit data captured successfully in: $OUT_DIR"
echo "=========================================================="
