# ==============================================================================
# Browser Hardening Compliance Audit Report & Evidence
# Generated for PAI-3 VULNAWEB - Universidad Pública U-Secure
# ==============================================================================

## 1. Executive Summary & Verification Matrix
The enterprise browser policies have been provisioned across corporate endpoints (Linux and Windows platforms) using native distribution policy templates:
- **Mozilla Firefox:** `/etc/firefox/policies/policies.json`
- **Chromium / Google Chrome:** `/etc/opt/chrome/policies/managed/corporate_policy.json` and `/etc/chromium/policies/managed/corporate_policy.json`

## 2. Policy Verification Audit Results

| Policy Directive | Status | Configured Value | Verification Target | Compliance Assessment |
|---|---|---|---|---|
| `HttpsOnlyMode` | **ACTIVE (LOCKED)** | `force_enabled` | `dom.security.https_only_mode` | **CONFORME (ENS MP.COM.2)** |
| `PasswordManagerEnabled` | **ACTIVE (LOCKED)** | `false` | `signon.rememberSignons` | **CONFORME (NIST SP 800-63B)** |
| `OfferToSaveLogins` | **ACTIVE (LOCKED)** | `false` | UI credential prompts disabled | **CONFORME** |
| `BlockAboutConfig` | **ACTIVE (LOCKED)** | `true` | Browser config modification blocked | **CONFORME** |
| `DisableTelemetry` | **ACTIVE (LOCKED)** | `true` | `toolkit.telemetry.enabled` | **CONFORME (RGPD / LOPD)** |
| `ExtensionSettings` | **ACTIVE (LOCKED)** | Blocklist `*`, Force `uBlock Origin` | Add-on installation manager | **CONFORME (CIS 3.1)** |
| `EnableTrackingProtection`| **ACTIVE (LOCKED)** | `Cryptomining: true, Fingerprinting: true` | Content blocking engine | **CONFORME** |
| `Permissions (Camera/Mic)`| **ACTIVE (LOCKED)** | `BlockNewRequests = true` | WebRTC / Hardware prompts | **CONFORME** |
| `network.trr.mode` (DoH) | **ACTIVE (LOCKED)** | `2` (Cloudflare/Quad9 DNS over HTTPS) | DNS transport resolution | **CONFORME** |
| `media.peerconnection.enabled`| **ACTIVE (LOCKED)**| `false` (WebRTC IP leak prevention) | Internal IP address exposure | **CONFORME** |
| `SSLVersionMin` | **ACTIVE (LOCKED)** | `tls1.2` | Legacy cipher deprecation | **CONFORME (NIST SP 800-52)** |

## 3. Policy File Hashes & Integrity
- **File:** `browser/firefox_policies.json`
  - SHA-256: `18f77d7f7226db2a9a9528d77c44be3161ce3879a7852c0aeb4dbd0b98eb6c0f`
- **File:** `browser/chrome_managed_policies.json`
  - SHA-256: `c8d19318b7600bbfa1dbdfd081f2be8d1222bfa3571d23ea3cfbc1e06e300180`
