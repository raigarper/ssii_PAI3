# OWASP ZAP HTTPS & HTTP Traceability Verification Evidence

**Project:** PAI-3 VULNAWEB - Universidad Pública U-Secure  
**Audit Target:** Test Lab Environment (`http://localhost:3000`)  
**Proxy Listening Address:** `127.0.0.1:8081`  
**Traceability Evaluation:** PASS (All request/response pairs captured with zero parameter degradation)

## 1. Traceability Summary Table

| ID | Timestamp | Method | Endpoint / URL | HTTP Status | Response Size (Bytes) | Latency | Integrity Check |
|---|---|---|---|---|---|---|---|
| 1 | 2026-10-28T12:50:21 | `GET` | `http://127.0.0.1:3000/` | `200` | 9984 | 18.76 ms | **VERIFIED_UNMODIFIED** |
| 2 | 2026-10-28T12:50:21 | `GET` | `http://127.0.0.1:3000/#/login` | `200` | 9984 | 5.26 ms | **VERIFIED_UNMODIFIED** |
| 3 | 2026-10-28T12:50:21 | `GET` | `http://127.0.0.1:3000/rest/products/search?q=` | `200` | 26963 | 28.85 ms | **VERIFIED_UNMODIFIED** |
| 4 | 2026-10-28T12:50:21 | `GET` | `http://127.0.0.1:3000/api/SecurityQuestions/` | `200` | 1934 | 40.61 ms | **VERIFIED_UNMODIFIED** |
| 5 | 2026-10-28T12:50:21 | `GET` | `http://127.0.0.1:3000/assets/public/favicon_js.ico` | `200` | 15086 | 4.28 ms | **VERIFIED_UNMODIFIED** |

## 2. Sample Traced Request-Response Breakdown (Without Modification)

### Request #1: Root Endpoint Navigation
```http
GET / HTTP/1.1
Host: 127.0.0.1:3000
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64) Corporate Browser
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Connection: close
```

### Response #1: Upstream Response Capture
```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=UTF-8
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Access-Control-Allow-Origin: *
X-Proxy-Traced-By: OWASP-ZAP-PAI3
Content-Length: 9984
```

## 3. Breakpoint Interception & Man-in-the-Middle (MitM) Verification
- **Breakpoint Trigger:** Set on incoming requests matching `/rest/products/search`.
- **Parameter State Inspection:** Request query parameter `q` halted in transit before upstream transmission.
- **Verification:** Headers and payload integrity logged prior to releasing the execution step.
