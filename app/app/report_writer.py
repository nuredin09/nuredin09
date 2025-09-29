"""
Report writer: writes a simple text report and optionally a PDF if reportlab installed.
"""
import json
from typing import Dict

# Try to import reportlab for PDF output (optional)
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
    _HAS_REPORTLAB = True
except Exception:
    _HAS_REPORTLAB = False

def write_text_report(report: Dict, out_path: str):
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("=== Android App Security Scanner Report ===\n\n")
        f.write("Metadata:\n")
        for k, v in report.get("metadata", {}).items():
            f.write(f"- {k}: {v}\n")
        f.write("\nFindings:\n")
        for i, item in enumerate(report.get("findings", []), start=1):
            typ = item.get("type", "info").upper()
            msg = item.get("message", "")
            f.write(f"{i}. [{typ}] {msg}\n")
            if item.get("evidence"):
                f.write(f"    Evidence: {str(item.get('evidence'))[:800]}\n")
        # include raw JSON at end for debugging
        f.write("\nRaw JSON:\n")
        f.write(json.dumps(report, indent=2, ensure_ascii=False))

def write_pdf_report(report: Dict, out_path: str):
    if not _HAS_REPORTLAB:
        raise RuntimeError("reportlab not installed")
    c = canvas.Canvas(out_path, pagesize=letter)
    c.setFont("Helvetica", 11)
    y = 750
    c.drawString(50, y, "Android App Security Scanner Report")
    y -= 25
    for k, v in report.get("metadata", {}).items():
        c.drawString(50, y, f"{k}: {v}")
        y -= 16
        if y < 80:
            c.showPage(); y = 750
    y -= 10
    c.drawString(50, y, "Findings:")
    y -= 20
    for item in report.get("findings", []):
        line = f"- [{item.get('type','info').upper()}] {item.get('message')}"
        c.drawString(50, y, line[:90])
        y -= 14
        if item.get("evidence"):
            evid = str(item.get("evidence"))
            c.drawString(60, y, f"evidence: {evid[:70]}")
            y -= 14
        if y < 80:
            c.showPage(); y = 750
    c.save()

def write_report(report: Dict, out_path: str):
    # Choose PDF if file extension is .pdf and reportlab is available
    if out_path.lower().endswith(".pdf"):
        if _HAS_REPORTLAB:
            write_pdf_report(report, out_path)
        else:
            # fallback: write text and suffix .txt to name
            write_text_report(report, out_path + ".txt")
    else:
        write_text_report(report, out_path)
