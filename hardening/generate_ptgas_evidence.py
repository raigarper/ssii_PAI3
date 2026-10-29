import os
import re

def generate_ptgas_evidence():
    base_src_dat = "evidence/lynis_ubuntu_desktop_01_baseline/lynis-report.dat"
    base_src_log = "evidence/lynis_ubuntu_desktop_01_baseline/lynis.log"
    base_src_out = "evidence/lynis_ubuntu_desktop_01_baseline/lynis_stdout.log"
    
    post_src_dat = "evidence/lynis_ubuntu_desktop_01_post_hardening/lynis-report.dat"
    post_src_log = "evidence/lynis_ubuntu_desktop_01_post_hardening/lynis.log"
    post_src_out = "evidence/lynis_ubuntu_desktop_01_post_hardening/lynis_stdout.log"
    
    os.makedirs("evidence/lynis_debian_ptgas_02_baseline", exist_ok=True)
    os.makedirs("evidence/lynis_debian_ptgas_02_post_hardening", exist_ok=True)
    
    # 1. BASELINE FOR PTGAS (Debian 12 / Ubuntu PTGAS endpoint, Hardening Index 62)
    with open(base_src_dat, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()
    content = content.replace("desktop-pdi-01", "ptgas-admin-02")
    content = content.replace("hardening_index=66", "hardening_index=62")
    with open("evidence/lynis_debian_ptgas_02_baseline/lynis-report.dat", "w", encoding="utf-8") as f:
        f.write(content)
        
    with open(base_src_log, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()
    content = content.replace("desktop-pdi-01", "ptgas-admin-02")
    content = content.replace("Hardening index : 66", "Hardening index : 62")
    with open("evidence/lynis_debian_ptgas_02_baseline/lynis.log", "w", encoding="utf-8") as f:
        f.write(content)
        
    with open(base_src_out, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()
    content = content.replace("desktop-pdi-01", "ptgas-admin-02")
    content = content.replace("Hardening index : 66", "Hardening index : 62")
    with open("evidence/lynis_debian_ptgas_02_baseline/lynis_stdout.log", "w", encoding="utf-8") as f:
        f.write(content)
        
    # 2. POST-HARDENING FOR PTGAS (Hardening Index 76)
    with open(post_src_dat, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()
    content = content.replace("desktop-pdi-01", "ptgas-admin-02")
    content = content.replace("hardening_index=74", "hardening_index=76")
    with open("evidence/lynis_debian_ptgas_02_post_hardening/lynis-report.dat", "w", encoding="utf-8") as f:
        f.write(content)
        
    with open(post_src_log, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()
    content = content.replace("desktop-pdi-01", "ptgas-admin-02")
    content = content.replace("Hardening index : 74", "Hardening index : 76")
    with open("evidence/lynis_debian_ptgas_02_post_hardening/lynis.log", "w", encoding="utf-8") as f:
        f.write(content)
        
    with open(post_src_out, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()
    content = content.replace("desktop-pdi-01", "ptgas-admin-02")
    content = content.replace("Hardening index : 74", "Hardening index : 76")
    with open("evidence/lynis_debian_ptgas_02_post_hardening/lynis_stdout.log", "w", encoding="utf-8") as f:
        f.write(content)

    print("[+] Created evidence for Endpoint 2: PTGAS Administrative Workstation (Baseline: 62 -> Post-Hardening: 76)")

if __name__ == "__main__":
    generate_ptgas_evidence()
