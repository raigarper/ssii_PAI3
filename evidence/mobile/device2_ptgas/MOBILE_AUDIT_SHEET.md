# Informe de Auditoría de Endpoint Móvil BYOD: Dispositivo 2: Terminal Personal PTGAS (Xiaomi Redmi Note 11)

- **Modelo:** `2201117TY`
- **Sistema Operativo:** `Android 12 (Snow Cone / MIUI 13)`
- **Herramienta Antivirus / DAST:** `Koodous Mobile Security + MobSF`
- **Fecha Auditoría:** `2026-10-28`

## 1. Estado Inicial de Postura (Línea Base)

| Vector de Seguridad | Evaluación Inicial | Nivel de Riesgo |
|---|---|---|
| `unknown_sources` | 0 (Disabled) | **BAJO** |
| `root_status` | Not detected (No SU binary, Bootloader locked) | **BAJO** |
| `os_patch_status` | 5 months outdated (HIGH RISK) | **ALTO** |
| `wifi_posture` | WPA2-Personal basic; open network profiles stored | **BAJO** |
| `bluetooth_state` | Disabled | **BAJO** |
| `malware_scan` | 0 Threats detected via Koodous rule engine | **BAJO** |
| `background_sockets` | 21 active connections (Xiaomi cloud sync daemons active) | **BAJO** |
| `critical_permissions` | Third-party keyboard utility holding READ_EXTERNAL_STORAGE and notification listener permission (HIGH RISK) | **ALTO** |

## 2. Medidas Correctoras de Bastionado Aplicadas

- [x] Applied manufacturer Over-The-Air (OTA) security firmware update bringing patch level to current supported cycle.
- [x] Replaced third-party custom keyboard with official AOSP keyboard with network connectivity blocked.
- [x] Revoked notification listener and storage access permissions for untrusted utility applications.
- [x] Purged insecure wireless network profiles and configured WPA2/WPA3-Enterprise 802.1X PEAP for campus connectivity.

## 3. Postura Post-Bastionado (Cumplimiento de Política)

| Vector de Seguridad | Estado Remediado | Cumplimiento Política Universidad |
|---|---|---|
| `unknown_sources` | **0 (STRICTLY DISABLED)** | **CONFORME** |
| `root_status` | **VERIFIED_INTACT (SELinux Enforcing)** | **CONFORME** |
| `os_patch_status` | **COMPLIANT (Updated to vendor latest)** | **CONFORME** |
| `wifi_posture` | **COMPLIANT (Enterprise 802.1X)** | **CONFORME** |
| `bluetooth_state` | **RESTRICTED** | **CONFORME** |
| `malware_scan` | **CLEAN (0 Threats detected)** | **CONFORME** |
| `background_sockets` | **AUDITED & RESTRICTED** | **CONFORME** |
| `critical_permissions` | **ISOLATED (Keylogger / notification risk mitigated)** | **CONFORME** |
| `hardening_posture` | **FULL COMPLIANCE (Hardened)** | **CONFORME** |
