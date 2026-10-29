#!/usr/bin/env bash
# ==============================================================================
# Helper to run Lynis audit and archive evidence for PAI-3
# Usage: ./run_lynis_audit.sh <baseline|post_hardening> <system_name>
# ==============================================================================

set -euo pipefail

STAGE="${1:-baseline}"
SYS_NAME="${2:-desktop_pdi_01}"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
OUTPUT_DIR="evidence/lynis_${SYS_NAME}_${STAGE}"

mkdir -p "$OUTPUT_DIR"

echo "=========================================================="
echo " Running Lynis Audit - System: $SYS_NAME | Stage: $STAGE"
echo "=========================================================="

if ! command -v lynis &>/dev/null; then
    echo "[!] Lynis is not installed. Installing lynis..."
    sudo apt-get update -y && sudo apt-get install -y lynis
fi

# Run the system audit non-interactively
sudo lynis audit system --quick --auditor "Security_Team_INSEGUS" | tee "$OUTPUT_DIR/lynis_stdout.log"

# Copy the Lynis output files
if [ -f /var/log/lynis.log ]; then
    sudo cp /var/log/lynis.log "$OUTPUT_DIR/lynis.log"
fi
if [ -f /var/log/lynis-report.dat ]; then
    sudo cp /var/log/lynis-report.dat "$OUTPUT_DIR/lynis-report.dat"
    
    echo ""
    echo "==================== AUDIT SUMMARY ===================="
    INDEX=$(grep "^hardening_index=" "$OUTPUT_DIR/lynis-report.dat" | cut -d= -f2 || echo "N/A")
    echo " Hardening Index achieved: [ $INDEX ]"
    echo " Report saved to: $OUTPUT_DIR"
    echo "========================================================"
fi
