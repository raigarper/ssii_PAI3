# Browser Hardening Justification & Configuration Guide

**Project:** PAI-3 VULNAWEB - Universidad Pública U-Secure  
**Target Applications:** Mozilla Firefox & Chromium/Google Chrome  
**Compliance Standards:** CIS Mozilla Firefox Benchmark, CIS Google Chrome Benchmark, ENS (Categoría Alta)

---

## 1. Technical Implementation Locations

### Mozilla Firefox:
- **Linux:** Place `firefox_policies.json` as `/usr/lib/firefox/distribution/policies.json` or `/etc/firefox/policies/policies.json`.
- **Windows:** Place file as `C:\Program Files\Mozilla Firefox\distribution\policies.json`.
- **Verification:** Navigate to `about:policies` in Firefox to verify that all policies are active and locked.

### Google Chrome / Chromium:
- **Linux:** Place `chrome_managed_policies.json` as `/etc/opt/chrome/policies/managed/corporate_policy.json` (or `/etc/chromium/policies/managed/corporate_policy.json`).
- **Windows:** Imported via Windows Registry (`HKLM\SOFTWARE\Policies\Google\Chrome`) or GPO.
- **Verification:** Navigate to `chrome://policy` to inspect applied corporate directives.

---

## 2. Policy Matrix and Threat Mitigation

| Directive / Setting | Configuration Value | Threat Mitigated & Rationale | Standard Alignment |
|---|---|---|---|
| **HttpsOnlyMode** | `force_enabled` | Prevents Man-in-the-Middle (MitM) eavesdropping, downgrade attacks (SSL-stripping), and plain-text transmission of credentials over untrusted Wi-Fi. | ENS MP.COM.2, CIS 1.1 |
| **PasswordManagerEnabled** / **OfferToSaveLogins** | `false` | Mitigates credential extraction by local malware or malicious scripts from browser SQLite storage. Forces utilization of corporate enterprise vaults. | CIS 2.1, NIST SP 800-63B |
| **BlockAboutConfig** | `true` | Prevents end-users from disabling security controls, lowering TLS minimum levels, or bypassing enterprise extensions. | ENS OP.ACC.1 |
| **DisableTelemetry** / **MetricsReportingEnabled** | `true` (`false` in Chrome) | Prevents unintentional exfiltration of confidential session metadata, URLs, and intranet topologies to third-party cloud services. | RGPD / LOPD-GDD, ENS |
| **ExtensionSettings** (Allowlist / Blocklist) | Block all (`*`), force-install `uBlock Origin` | Prevents installation of rogue browser extensions containing keyloggers, adware, or credential scrapers. Enforces ad-blocking and tracking prevention. | CIS 3.1, OWASP Top 10 |
| **Permissions (Camera, Mic, Location, Notifications)** | `BlockNewRequests = true` / Deny by default | Mitigates drive-by surveillance, unauthorized eavesdropping, and push notification spam / phishing lures. | CIS 4.2 |
| **DNS over HTTPS (network.trr.mode)** | `2` (Enabled with fallback) | Encrypts DNS queries preventing local network eavesdropping, DNS hijacking, and ISP snooping. | RFC 8484, ENS |
| **privacy.firstparty.isolate** | `true` | Enforces First-Party Isolation, preventing cross-site tracking and cookie leaks between disparate web domains. | CIS Privacy Profile |
| **media.peerconnection.enabled** | `false` | Mitigates WebRTC IP leaks that can reveal real client IP addresses even when browsing through corporate VPNs or proxies. | OWASP Client-Side Security |
| **SSLVersionMin** | `tls1.2` | Deprecates vulnerable legacy cryptographic protocols (SSLv3, TLS 1.0, TLS 1.1) vulnerable to POODLE, BEAST, and SWEET32. | NIST SP 800-52 Rev 2 |
| **ImportEnterpriseRoots** | `true` | Allows corporate intercepting proxies (e.g., OWASP ZAP or corporate CASB) to be trusted seamlessly via system CA store. | Audit / DAST Inspection |
