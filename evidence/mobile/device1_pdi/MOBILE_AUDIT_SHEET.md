# Informe de Auditoría de Endpoint Móvil BYOD: Dispositivo 1: Smartphone Personal PDI (Samsung Galaxy S22)

- **Modelo:** `SM-S901B/DS`
- **Sistema Operativo:** `Android 13 (Tiramisu)`
- **Herramienta Antivirus / DAST:** `Malwarebytes Mobile Security v4.0.5`
- **Fecha Auditoría:** `2026-10-28`

## 1. Estado Inicial de Postura (Línea Base)

| Vector de Seguridad | Evaluación Inicial | Nivel de Riesgo |
|---|---|---|
| `unknown_sources` | 1 (ENABLED for Browser & Telegram - VULNERABILITY) | **ALTO** |
| `root_status` | Not detected (No SU binary in /system/xbin/su, SELinux: Enforcing) | **BAJO** |
| `os_patch_status` | Up to date (Within 60-day window) | **BAJO** |
| `wifi_posture` | WPA2-Enterprise (eduroam) active; auto-connect open Wi-Fi: Enabled (RISK) | **MEDIO** |
| `bluetooth_state` | Active / Discoverable during corporate web sessions (RISK) | **MEDIO** |
| `malware_scan` | 0 Malicious APKs detected; 1 Adware PUP flagged (Cleaned) | **BAJO** |
| `background_sockets` | 14 active ESTABLISHED TCP sockets; no suspicious C2 connections | **BAJO** |
| `critical_permissions` | 2 third-party apps granted SYSTEM_ALERT_WINDOW; 1 app with Accessibility Service enabled (HIGH RISK) | **ALTO** |

## 2. Medidas Correctoras de Bastionado Aplicadas

- [x] Revoked 'Install Unknown Apps' (sideloading) permission for all browsers and file managers (install_non_market_apps = 0).
- [x] Disabled automatic Wi-Fi join for unencrypted/open SSIDs and purged unsecured networks from profile cache.
- [x] Enforced Bluetooth interface deactivation during active sessions accessing university electronic services.
- [x] Revoked accessibility and screen overlay permissions for third-party tools; uninstalled flagged adware PUP.

## 3. Postura Post-Bastionado (Cumplimiento de Política)

| Vector de Seguridad | Estado Remediado | Cumplimiento Política Universidad |
|---|---|---|
| `unknown_sources` | **0 (STRICTLY DISABLED)** | **CONFORME** |
| `root_status` | **VERIFIED_INTACT (SELinux Enforcing)** | **CONFORME** |
| `os_patch_status` | **COMPLIANT** | **CONFORME** |
| `wifi_posture` | **COMPLIANT (WPA2/WPA3-Enterprise only)** | **CONFORME** |
| `bluetooth_state` | **RESTRICTED / DISABLED** | **CONFORME** |
| `malware_scan` | **CLEAN (0 Threats / 0 PUPs)** | **CONFORME** |
| `background_sockets` | **AUDITED (0 Unsanctioned sockets)** | **CONFORME** |
| `critical_permissions` | **ISOLATED (Dangerous permissions revoked)** | **CONFORME** |
| `hardening_posture` | **FULL COMPLIANCE (Hardened)** | **CONFORME** |
