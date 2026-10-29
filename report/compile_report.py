#!/usr/bin/env python3
"""
Compiles report/INFORME_AUDITORIA_PAI3.md into a professional PDF
using markdown-pdf
"""

import os
from markdown_pdf import Section, MarkdownPdf

MD_FILE = "report/INFORME_AUDITORIA_PAI3.md"
PDF_FILE = "report/INFORME_AUDITORIA_PAI3.pdf"

def compile_pdf():
    print(f"[*] Reading {MD_FILE}...")
    with open(MD_FILE, "r", encoding="utf-8") as f:
        md_content = f.read()

    print("[*] Compiling Markdown to PDF...")
    pdf = MarkdownPdf(toc_level=2)
    pdf.add_section(Section(md_content))
    pdf.save(PDF_FILE)
    print(f"[+] PDF compiled successfully: {PDF_FILE}")
    print(f"[+] Output file size: {os.path.getsize(PDF_FILE) / 1024:.2f} KB")

if __name__ == "__main__":
    compile_pdf()
