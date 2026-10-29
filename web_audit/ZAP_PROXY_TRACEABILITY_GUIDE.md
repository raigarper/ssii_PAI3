# OWASP ZAP HTTPS Interception & Traceability Guide

**Project:** PAI-3 VULNAWEB - Universidad Pública U-Secure  
**Objective:** Deploy and configure an intercepting proxy (OWASP ZAP) to demonstrate end-to-end traceability of HTTP/HTTPS traffic without parameter modification, followed by breakpoint manipulation.

---

## 1. Proxy Architecture Setup

1. **Launch OWASP ZAP**:
   - Go to **Tools > Options > Network > Local Servers/Proxies** (or **Options > Local Proxy** in older ZAP versions).
   - Set **Address / IP**: `localhost` (or `127.0.0.1`).
   - Set **Port**: `8081`.
   - Ensure the server is listening (`netstat -ano | findstr 8081`).

2. **Generate and Export the Root CA Certificate**:
   - In ZAP: **Tools > Options > Dynamic SSL Certificates**.
   - Click **Generate** if not already generated.
   - Click **Save** and export the certificate as `owasp_zap_root_ca.cer`.

3. **Install CA Certificate in the Browser (e.g., Firefox)**:
   - In Firefox: **Settings > Privacy & Security > Certificates > View Certificates...**.
   - Select the **Authorities** tab and click **Import...**.
   - Choose `owasp_zap_root_ca.cer`.
   - Check the box: `[x] Trust this CA to identify websites` and confirm.

4. **Configure Browser Network Proxy**:
   - In Firefox: **Settings > General > Network Settings > Settings...**.
   - Select **Manual proxy configuration**.
   - Set **HTTP Proxy**: `127.0.0.1`, **Port**: `8081`.
   - Check `[x] Also use this proxy for FTP and HTTPS`.
   - Clear the "No proxy for" field to ensure localhost can be intercepted.

---

## 2. Test Plan 1: Verifying Passive Traceability (Without Modification)

1. Navigate to the local educational lab application (e.g., `http://localhost:3000` or an HTTPS test endpoint).
2. Perform standard authentication / navigation actions:
   - Access the login portal.
   - Enter credentials.
   - Navigate through catalog or profile pages.
3. In OWASP ZAP, examine the **History** tab:
   - **Traceability Verification:** Observe sequential requests ordered by ID and timestamp.
   - Double-click a request to inspect the **Request Header** (`Method`, `URL`, `User-Agent`, `Cookie`, `Authorization`).
   - Inspect the **Request Body / Parameters** confirming exact byte transmission without alteration.
   - Inspect the **Response Header** (`HTTP Status Code`, `Set-Cookie`, security headers like `Content-Security-Policy`, `X-Frame-Options`).
   - Inspect the **Response Body** (HTML / JSON).
4. **Deliverable Evidence:**
   - Screenshot of ZAP History showing continuous session traffic.
   - Screenshot of Request and Response panels verifying complete traceability.
   - Export HTTP message log (`File > Export Selected Messages` or `.har` export).

---

## 3. Test Plan 2: Breakpoint & Active Interception Demonstration

1. In ZAP's main toolbar, locate the green circular **Set Breakpoint on all requests** button (turn to Red).
2. In the browser, submit an action (such as a login or search form).
3. **Execution Pause:**
   - ZAP halts execution before forwarding the packet to the server.
   - The **Break** tab opens, displaying editable fields for all HTTP headers and query/body parameters.
4. **Parameter Manipulation Test:**
   - Alter a designated testing parameter.
   - Click the **Step** button or **Continue** button to release the request to the upstream server.
   - Observe the subsequent server response in the Response Break tab.
5. **Deliverable Evidence:**
   - Screenshot showing the intercepted request halted at the Breakpoint.
   - Screenshot demonstrating parameter modification before release.
   - Screenshot showing server response handling the modified input.
