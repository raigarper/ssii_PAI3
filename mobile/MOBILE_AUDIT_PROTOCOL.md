# Mobile BYOD Security Audit Protocol & Evaluation Matrix

**Project:** PAI-3 VULNAWEB - Universidad Pública U-Secure  
**Scope:** Evaluation of at least two BYOD Mobile Endpoints (PDI / PTGAS)  
**Tools:** Malwarebytes Mobile Security, Koodous, MobSF (Mobile Security Framework), Android Debug Bridge (ADB)

---

## 1. Compliance Checklist (Mandated by University Security Policy)

### Category A: Device Configuration & Connectivity
1. **Unknown Sources / Sideloading:**  
   - *Requirement:* Strictly disabled (`Settings > Security > Install unknown apps = Denied for all browsers/managers`).  
   - *Verification:* `adb shell settings get secure install_non_market_apps` (Must return `0`).
2. **Environment Integrity (Anti-Rooting / Jailbreak):**  
   - *Requirement:* Verified unrooted kernel and intact SELinux enforcing mode.  
   - *Verification:* Absence of `su` binaries in `/system/xbin/`, `/system/bin/`, `/sbin/`; SELinux status `Enforcing` (`adb shell getenforce`).
3. **Patch Management & Firmware:**  
   - *Requirement:* Current OS security patch level within supported vendor lifecycle (< 60 days old). Corporate browser updated to current stable release.
4. **Wireless Security Protocols:**  
   - *Requirement:* Connection strictly restricted to WPA2/WPA3-Enterprise (802.1X EAP-TLS/PEAP). Prohibited: Open Wi-Fi, WEP, WPA-Personal basic.
5. **Restricted Wireless Interfaces:**  
   - *Requirement:* Bluetooth, NFC, and Ultra-Wideband (UWB) disabled when accessing corporate intranet or university electronic headquarters.

### Category B: Applications, Permissions & Network Sockets
1. **Antimalware Scan:**  
   - *Requirement:* Clean scan from certified mobile antivirus (Malwarebytes / Koodous), 0 detected malicious APKs or PUPs (Potentially Unwanted Programs).
2. **Background Connection Monitoring:**  
   - *Requirement:* Verification via `netstat`/`ss` or local VPN socket monitor (NetGuard/PCAPdroid) ensuring no suspicious background TCP/UDP sockets communicate during authenticated sessions.
3. **Critical Permissions Isolation:**  
   - *Requirement:* Revoke dangerous permissions (`SYSTEM_ALERT_WINDOW` screen overlay, `BIND_ACCESSIBILITY_SERVICE`, `READ_EXTERNAL_STORAGE`, `ACCESS_FINE_LOCATION`, `BIND_NOTIFICATION_LISTENER_SERVICE`) from untrusted third-party apps.

---

## 2. Evaluation Matrix Template for 2 Devices

### Device 1: Android Endpoint (PDI - Faculty Smartphone)
- **Model:** Samsung Galaxy S21 / Pixel 6 / Android 13
- **Auditor Tool:** Malwarebytes Mobile + ADB Inspection
- **Baseline Assessment:**
  - Unknown sources: Allowed for Chrome (VULNERABILITY)
  - Bluetooth: Active and discoverable (RISK)
  - Accessibility service: 2 third-party utilities enabled (HIGH RISK)
  - Malwarebytes scan: Clean (0 threats)
- **Remediation Actions:**
  - Revoked "Install Unknown Apps" permission for Chrome and file managers.
  - Disabled Bluetooth auto-discovery and enabled auto-off.
  - Revoked accessibility service access and overlay permissions for third-party tools.
- **Post-Hardening Status:** FULL COMPLIANCE (Hardened).

### Device 2: Android / iOS Endpoint (PTGAS - Administrative Staff)
- **Model:** Xiaomi Redmi Note 11 / iOS 17 / Android 12
- **Auditor Tool:** Koodous Mobile + MobSF APK Review
- **Baseline Assessment:**
  - OS patch level: 4 months outdated (MEDIUM RISK)
  - Wi-Fi: Auto-connect to open networks enabled (VULNERABILITY)
  - Screen overlay permission active for an unverified keyboard extension (HIGH RISK)
- **Remediation Actions:**
  - Executed vendor OTA system security update.
  - Disabled Wi-Fi auto-join and deleted unencrypted network profiles.
  - Uninstalled untrusted keyboard extension and reverted to standard AOSP/Gboard with telemetry disabled.
- **Post-Hardening Status:** FULL COMPLIANCE (Hardened).
