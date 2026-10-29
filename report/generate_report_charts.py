import os
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

os.makedirs("report/figures", exist_ok=True)

# 1. Chart: Lynis Hardening Index Comparison
def create_lynis_chart():
    fig, ax = plt.subplots(figsize=(8, 4.5), dpi=300)
    
    systems = ['Endpoint 1 (PDI Ubuntu 22.04)', 'Endpoint 2 (PTGAS Debian 12)']
    baseline_scores = [66, 62]
    hardened_scores = [74, 76]
    target_threshold = 70
    
    x = np.arange(len(systems))
    width = 0.32
    
    rects1 = ax.bar(x - width/2, baseline_scores, width, label='Línea Base (Pre-Hardening)', color='#d9534f', edgecolor='black', alpha=0.85)
    rects2 = ax.bar(x + width/2, hardened_scores, width, label='Post-Bastionado (Hardened)', color='#2e7d32', edgecolor='black', alpha=0.9)
    
    # Target line
    ax.axhline(y=target_threshold, color='#ff9800', linestyle='--', linewidth=2, label='Umbral Mínimo Requerido (Index = 70)')
    
    ax.set_ylabel('Hardening Index (Lynis / CIS Benchmark)', fontsize=11, fontweight='bold')
    ax.set_title('Evolución del Hardening Index en Endpoints Universitarios', fontsize=12, fontweight='bold', pad=12)
    ax.set_xticks(x)
    ax.set_xticklabels(systems, fontsize=10, fontweight='bold')
    ax.set_ylim(0, 100)
    ax.grid(axis='y', linestyle=':', alpha=0.6)
    ax.legend(loc='lower right', frameon=True, facecolor='white', framealpha=0.95)
    
    # Add value labels
    for rect in rects1:
        height = rect.get_height()
        ax.annotate(f'{height}/100',
                    xy=(rect.get_x() + rect.get_width() / 2, height),
                    xytext=(0, 4), textcoords="offset points",
                    ha='center', va='bottom', fontsize=10, fontweight='bold', color='#b71c1c')
                    
    for rect in rects2:
        height = rect.get_height()
        ax.annotate(f'{height}/100',
                    xy=(rect.get_x() + rect.get_width() / 2, height),
                    xytext=(0, 4), textcoords="offset points",
                    ha='center', va='bottom', fontsize=10, fontweight='bold', color='#1b5e20')
                    
    plt.tight_layout()
    chart_path = "report/figures/lynis_hardening_comparison.png"
    plt.savefig(chart_path)
    plt.close()
    print(f"[+] Saved: {chart_path}")

# 2. Chart: Web Fuzzing Responses & Vulnerability Breakdown
def create_fuzzer_chart():
    fig, ax = plt.subplots(figsize=(8, 4.2), dpi=300)
    
    categories = ['SQL Injection\n(jbrofuzz Auth/Union)', 'Cross-Site Scripting\n(Reflected/DOM XSS)', 'Path Traversal\n(Poison Null Byte)', 'SQL Error Probes\n(Syntax Trigger)', 'Benign Searches\n(Baseline Controls)']
    counts = [6, 4, 3, 7, 4]
    vulnerable_counts = [5, 4, 3, 7, 0]
    
    x = np.arange(len(categories))
    width = 0.35
    
    rects1 = ax.bar(x - width/2, counts, width, label='Payloads Inyectados (Total 24)', color='#1976d2', edgecolor='black', alpha=0.85)
    rects2 = ax.bar(x + width/2, vulnerable_counts, width, label='Respuestas Anómalas / Vulnerables', color='#e65100', edgecolor='black', alpha=0.9)
    
    ax.set_ylabel('Número de Pruebas Automatizadas', fontsize=11, fontweight='bold')
    ax.set_title('Resultados de Fuzzing Automatizado DAST (OWASP ZAP - VulnaWeb)', fontsize=12, fontweight='bold', pad=12)
    ax.set_xticks(x)
    ax.set_xticklabels(categories, fontsize=9, fontweight='bold')
    ax.set_ylim(0, 10)
    ax.grid(axis='y', linestyle=':', alpha=0.6)
    ax.legend(loc='upper right', frameon=True)
    
    for rect in rects2:
        height = rect.get_height()
        if height > 0:
            ax.annotate(f'{height}',
                        xy=(rect.get_x() + rect.get_width() / 2, height),
                        xytext=(0, 3), textcoords="offset points",
                        ha='center', va='bottom', fontsize=9, fontweight='bold', color='#bf360c')
                        
    plt.tight_layout()
    chart_path = "report/figures/zap_fuzzer_chart.png"
    plt.savefig(chart_path)
    plt.close()
    print(f"[+] Saved: {chart_path}")

# 3. Chart: Mobile Security Compliance
def create_mobile_chart():
    fig, ax = plt.subplots(figsize=(8, 4.2), dpi=300)
    
    controls = [
        'Anti-Rooting\n(Integridad)',
        'Sideloading\n(Unknown Sources)',
        'Parches SO\n(Actualización)',
        'Wi-Fi Abierta\n(Restricción)',
        'Bluetooth\n(Acceso Sede)',
        'Anti-Malware\n(Escaneo)',
        'Sockets Red\n(Fondo)',
        'Permisos\n(Aislamiento)'
    ]
    
    pdi_scores = [100, 100, 100, 100, 100, 100, 100, 100] # Real Pixel 6a
    ptgas_scores = [100, 80, 85, 100, 90, 90, 85, 90]    # AVD Virtual
    
    x = np.arange(len(controls))
    width = 0.35
    
    ax.bar(x - width/2, pdi_scores, width, label='Dispositivo 1: Físico BYOD (Pixel 6a)', color='#0288d1', edgecolor='black', alpha=0.85)
    ax.bar(x + width/2, ptgas_scores, width, label='Dispositivo 2: Virtual AVD (Android 11)', color='#7b1fa2', edgecolor='black', alpha=0.85)
    
    ax.set_ylabel('Cumplimiento Política Universidad (%)', fontsize=11, fontweight='bold')
    ax.set_title('Auditoría de Seguridad Dispositivos Móviles (Categorías A y B)', fontsize=12, fontweight='bold', pad=12)
    ax.set_xticks(x)
    ax.set_xticklabels(controls, fontsize=8, fontweight='bold', rotation=15)
    ax.set_ylim(0, 115)
    ax.grid(axis='y', linestyle=':', alpha=0.6)
    ax.legend(loc='lower right', frameon=True)
    
    plt.tight_layout()
    chart_path = "report/figures/mobile_compliance_chart.png"
    plt.savefig(chart_path)
    plt.close()
    print(f"[+] Saved: {chart_path}")

if __name__ == "__main__":
    create_lynis_chart()
    create_fuzzer_chart()
    create_mobile_chart()
