# ==============================================================================
# Packaging script for PAI-3 Deliverable
# Creates PAI3-ST<TeamNum>.zip with all required deliverables and structure
# Usage: powershell -ExecutionPolicy Bypass -File .\package_deliverable.ps1 -TeamNumber 01
# ==============================================================================

param(
    [Parameter(Mandatory=$false)]
    [string]$TeamNumber = "02"
)

$ZipName = "PAI3-ST$TeamNumber.zip"
$RootPath = $PSScriptRoot

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Packaging PAI-3 Deliverable: $ZipName" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# Ensure evidence directory exists
if (-not (Test-Path "$RootPath\evidence")) {
    New-Item -ItemType Directory -Path "$RootPath\evidence" | Out-Null
}

# Remove existing zip if present
if (Test-Path "$RootPath\$ZipName") {
    Remove-Item "$RootPath\$ZipName" -Force
    Write-Host "[+] Removed previous $ZipName" -ForegroundColor Yellow
}

# Items to include in the submission zip
$ItemsToZip = @(
    "report",
    "evidence",
    "hardening",
    "browser",
    "mobile",
    "web_audit"
)

# Check presence of key files
$KeyFiles = @(
    "report\INFORME_AUDITORIA_PAI3.pdf",
    "report\INFORME_AUDITORIA_PAI3.tex",
    "hardening\harden_linux.sh",
    "hardening\run_lynis_audit.sh",
    "hardening\custom.prf",
    "browser\firefox_policies.json",
    "browser\chrome_managed_policies.json",
    "browser\BROWSER_HARDENING_JUSTIFICATION.md",
    "mobile\MOBILE_AUDIT_PROTOCOL.md",
    "mobile\run_live_android_audit.py",
    "web_audit\ZAP_PROXY_TRACEABILITY_GUIDE.md",
    "web_audit\OWASP_TOP10_DEFENSIVE_REMEDIATION_PLAN.md",
    "web_audit\run_zap_fuzzing.py",
    "web_audit\generate_detailed_pocs.py",
    "evidence\lynis_ubuntu_desktop_01_post_hardening\lynis-report.dat",
    "evidence\lynis_debian_ptgas_02_post_hardening\lynis-report.dat",
    "evidence\mobile\device1_real_phone\system_properties_sanitized.txt",
    "evidence\mobile\device2_virtual_endpoint\system_properties.txt",
    "evidence\web_audit\zap_traceability_records.json",
    "evidence\web_audit\zap_fuzzer_sqli_results.csv",
    "evidence\web_audit\vuln1_sqli_poc.txt",
    "evidence\web_audit\vuln2_xss_poc.txt",
    "evidence\web_audit\vuln3_path_traversal_poc.txt",
    "evidence\web_audit\zap_breakpoint_tampering_trace.txt"
)

Write-Host "[*] Verifying critical project files..." -ForegroundColor Gray
foreach ($file in $KeyFiles) {
    if (Test-Path "$RootPath\$file") {
        Write-Host "  [OK] $file" -ForegroundColor Green
    } else {
        Write-Host "  [MISSING] $file" -ForegroundColor Red
    }
}

Write-Host "[*] Creating deliverable ZIP archive..." -ForegroundColor Gray
Compress-Archive -Path $ItemsToZip -DestinationPath "$RootPath\$ZipName" -Force

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Deliverable packaged successfully: $ZipName" -ForegroundColor Green
Write-Host " File size: $((Get-Item "$RootPath\$ZipName").Length / 1KB) KB" -ForegroundColor Green
Write-Host " Ready to upload to virtual learning platform before deadline!" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan
