# Comprehensive OWASP Top 10 (Web & API Security 2023) Defensive Remediation Plan

**Project:** PAI-3 VULNAWEB - Universidad Pública U-Secure  
**Prepared for:** INSEGUS Security Audit Board  
**Target Architecture:** University Web Applications, REST APIs & Academic Sede Electrónica  
**Compliance Standards:** OWASP Top 10:2021 (Web), OWASP API Security Top 10:2023, NIST SP 800-53, ENS Categoría Alta

---

## 1. Executive Summary & Regulatory Framework

Modern higher-education platforms (such as the audited platform) heavily utilize REST APIs and Single Page Application (SPA) architectures that exchange structured JSON payloads. Consequently, this remediation plan bridges traditional web application risks with the **OWASP API Security Top 10 (2023)** standard, providing concrete architectural controls and defensive source code remediation for:
1. **Backend Injection & SQLi** *(OWASP Web A03:2021 – Injection | OWASP API8:2023 – Security Misconfiguration / API10:2023 – Unsafe Consumption)*
2. **Cross-Site Scripting (XSS) & Insecure JSON Rendering** *(OWASP Web A03:2021 – Injection | OWASP API8:2023 – Security Misconfiguration)*
3. **Path Traversal & Broken Authorization** *(OWASP Web A01:2021 – Broken Access Control | OWASP API1:2023 – Broken Object Level Authorization - BOLA)*
4. **API Authentication, Rate Limiting & Resource Consumption** *(OWASP API2:2023 – Broken Authentication | OWASP API4:2023 – Unrestricted Resource Consumption)*

---

## 2. Vulnerability 1: SQL Injection (SQLi) & Backend Injection in REST APIs

### 2.1 Threat Description & Impact
Untrusted input passed via URL query strings or JSON request bodies is concatenated directly into dynamic SQL/ORM queries, allowing an adversary to bypass authentication, extract student/faculty academic records, or modify database entries.

### 2.2 Root Cause
String concatenation and dynamic query assembly in API endpoint controllers without parameter binding.

### 2.3 Defensive Remediation & Code Patches

#### A. Enforce Parameterized Queries / Prepared Statements
All database access must utilize parameterized queries where parameter placeholders are bound separately by the database engine driver.

**Vulnerable REST Controller Pattern (PHP/PDO):**
```php
// INSECURE: Direct concatenation from JSON body
$data = json_decode(file_get_contents('php://input'), true);
$query = "SELECT * FROM users WHERE email = '" . $data['email'] . "' AND password = '" . $data['password'] . "'";
$result = $db->query($query);
```

**Remediated REST Controller Pattern (Prepared Statements):**
```php
// SECURE: Parameterized query with strict type binding
$data = json_decode(file_get_contents('php://input'), true);

$stmt = $db->prepare('SELECT id, email, password_hash, role FROM users WHERE email = :email LIMIT 1');
$stmt->execute([':email' => $data['email']]);
$user = $stmt->fetch();

if ($user && password_verify($data['password'], $user['password_hash'])) {
    // Issue cryptographically signed JWT or secure session cookie
}
```

#### B. Principle of Least Privilege in Database Accounts
- The web application and API database user must not hold administrative privileges (`DBA`, `SUPERUSER`, `GRANT`).
- Restrict privileges to only `SELECT`, `INSERT`, `UPDATE`, and `DELETE` on specific operational tables.

---

## 3. Vulnerability 2: Cross-Site Scripting (XSS) & Client-Side Context Insecurity

### 3.1 Threat Description & Impact
Arbitrary JavaScript injected into the application or returned through API endpoints executes in the context of the victim's browser session. Allows session hijacking (stealing unflagged tokens/cookies), DOM defacement, phishing redirects, or unauthorized user impersonation.

### 3.2 Root Cause
Rendering raw, unescaped user inputs directly into HTML contexts without contextual output encoding, or directly assigning untrusted API data to dangerous DOM sinks (`innerHTML`, `v-html`).

### 3.3 Defensive Remediation & Code Patches

#### A. Contextual Output Encoding & DOM Sanitization
Before injecting untrusted data into an HTML document or DOM sink, encode special characters based on the context:

**Vulnerable Pattern:**
```javascript
// INSECURE: Direct DOM insertion from API response
document.getElementById("profile").innerHTML = userApiData.bio;
```

**Remediated Pattern (Safe Text Content or DOMPurify):**
```javascript
// SECURE: Safe DOM text assignment (no HTML parsing)
document.getElementById("profile").textContent = userApiData.bio;

// Or when HTML formatting is strictly required:
document.getElementById("profile").innerHTML = DOMPurify.sanitize(userApiData.bio);
```

#### B. Cookie Security Flags for API Sessions
Mark all authentication cookies with the `HttpOnly`, `Secure`, and `SameSite` attributes:
```http
Set-Cookie: session_token=xxxxxx; Path=/; Secure; HttpOnly; SameSite=Strict
```

#### C. Strict Content Security Policy (CSP) (OWASP API8:2023)
Implement a robust Content Security Policy header rejecting inline scripts (`unsafe-inline`) and restricting script origins:
```http
Content-Security-Policy: default-src 'self'; script-src 'self' https://trustedscripts.university.edu; object-src 'none'; base-uri 'self';
```

---

## 4. Vulnerability 3: Path Traversal & Broken Object Level Authorization (BOLA)

### 4.1 Threat Description & Impact
File parameters or resource identifiers (`/api/documents/{id}`) allow directory traversal sequences (`../`) or direct ID enumeration, enabling unauthorized access to configuration files, system credentials, or records belonging to other university students (BOLA / Path Traversal).

### 4.2 Root Cause
Directly passing user-supplied file names or resource IDs to filesystem/database APIs without boundary verification and session ownership validation.

### 4.3 Defensive Remediation & Code Patches

#### A. Object Level Authorization Check (OWASP API1:2023 - BOLA)
Every API request accessing a file or record MUST verify that the authenticated user owns or has explicit permission for the requested entity:
```php
// SECURE: Explicit authorization verification before serving document
$documentId = (int)$_GET['id'];
$currentUser = auth()->user();

$stmt = $db->prepare('SELECT file_path FROM documents WHERE id = :id AND owner_id = :owner_id');
$stmt->execute([':id' => $documentId, ':owner_id' => $currentUser->id]);
$doc = $stmt->fetch();

if (!$doc) {
    http_response_code(403);
    die(json_encode(["error" => "Access denied: Unauthorized resource request."]));
}
```

#### B. Path Canonicalization & Root Boundary Check
Strip directory traversal indicators using `basename()` and verify that the resolved path begins with the authorized base directory:
```php
$base_dir = '/var/www/uploads/academic_reports/';
$real_base = realpath($base_dir);
$safe_filename = basename($doc['file_path']);
$resolved_path = realpath($base_dir . $safe_filename);

if ($resolved_path === false || strpos($resolved_path, $real_base) !== 0) {
    http_response_code(403);
    die(json_encode(["error" => "Path traversal detected."]));
}
readfile($resolved_path);
```

---

## 5. Architectural Defense-in-Depth (OWASP API Security 2023 Matrix)

| OWASP API 2023 Standard | Threat Class | Primary Architectural Control | Implementation Mechanism |
|---|---|---|---|
| **API1:2023 - BOLA** | Broken Object Level Authorization | Contextual ownership validation | Attribute-Based Access Control (ABAC) in API gateway and controllers. |
| **API2:2023 - Broken Authentication** | Token hijacking / brute force | Secure token lifetime & MFA | JWT signing with RS256, short TTL (15 min), Refresh Token Rotation. |
| **API3:2023 - BOPLA** | Object property exposure | Strict Data Transfer Objects (DTOs) | Allowlisting allowed JSON input fields; stripping sensitive fields on output. |
| **API4:2023 - Unrestricted Resource** | DoS / Brute-force flooding | Rate limiting & payload throttling | Gateway rate limits (e.g., 100 req/min per IP/token) and body size caps. |
| **API5:2023 - BFLA** | Broken Function Authorization | Role-based endpoint guards | Middleware enforcing admin roles on privileged routes (`/api/admin/*`). |
| **API7:2023 - SSRF** | Server Side Request Forgery | Outbound egress URL filtering | Network isolation and allowlisting permitted destination domains. |
| **API8:2023 - Misconfiguration** | Insecure headers & verbose errors | HTTP header hardening | Enforcing HSTS, CSP, `X-Content-Type-Options: nosniff`, sanitizing error traces. |
| **API9:2023 - Inventory Management** | Shadow & deprecated APIs | API gateway routing catalog | Strict API versioning (`/v1`, `/v2`) and automated Swagger/OpenAPI documentation. |
