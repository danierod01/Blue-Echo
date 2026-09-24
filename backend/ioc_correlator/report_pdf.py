"""Generación del informe PDF de un escaneo (roadmap F4).

Usa fpdf2 (Python puro, sin dependencias de sistema) para no complicar el
despliegue en la imagen `python:3.11-slim`. Produce un informe con el score,
el veredicto, la tabla de resultados por fuente, el análisis de IA y las
técnicas MITRE ATT&CK detectadas.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from fpdf import FPDF

# Colores por veredicto (RGB), coherentes con la UI del dashboard.
_VERDICT_COLOR: dict[str, tuple[int, int, int]] = {
    "critical": (239, 68, 68),
    "malicious": (249, 115, 22),
    "suspicious": (234, 179, 8),
    "clean": (34, 197, 94),
    "pcap": (168, 85, 247),
}
_VERDICT_LABEL = {
    "critical": "CRITICO",
    "malicious": "MALICIOSO",
    "suspicious": "SOSPECHOSO",
    "clean": "LIMPIO",
}
_DEFAULT_COLOR = (100, 116, 139)

# Sustituciones de caracteres Unicode no representables en latin-1 (fuentes
# core de fpdf2). Evita excepciones al renderizar texto en español.
_REPLACEMENTS = {
    "—": "-", "–": "-", "‘": "'", "’": "'",
    "“": '"', "”": '"', "…": "...", "≥": ">=",
    "≤": "<=", "→": "->", "•": "-", " ": " ",
}


def _latin1(text: str) -> str:
    """Normaliza un texto para que las fuentes core de fpdf2 lo acepten."""
    if not text:
        return ""
    for src, dst in _REPLACEMENTS.items():
        text = text.replace(src, dst)
    return text.encode("latin-1", errors="replace").decode("latin-1")


def _strip_markdown(text: str) -> str:
    """El análisis de IA viene en Markdown; se aplana para el PDF."""
    text = re.sub(r"^#{1,6}\s*", "", text, flags=re.MULTILINE)  # títulos
    text = re.sub(r"\*\*(.+?)\*\*", r"\1", text)                 # negritas
    text = re.sub(r"`(.+?)`", r"\1", text)                       # código inline
    return text.strip()


class _ReportPDF(FPDF):
    def __init__(self, ioc_value: str) -> None:
        super().__init__(orientation="P", unit="mm", format="A4")
        self._ioc = _latin1(ioc_value)
        self.set_auto_page_break(auto=True, margin=18)

    def footer(self) -> None:  # noqa: D401 - override de fpdf2
        self.set_y(-15)
        self.set_font("Helvetica", size=7)
        self.set_text_color(150, 150, 150)
        self.cell(
            0, 10,
            _latin1(f"Blue-Echo - Informe de {self._ioc} - pagina {self.page_no()}"),
            align="C",
        )


def build_scan_pdf(scan: Any) -> bytes:
    """Renderiza un ScanResponse (o equivalente) a bytes PDF.

    Se espera que `scan` exponga: ioc_value, ioc_type, score, verdict,
    ai_summary, created_at, connector_results (dict de objetos con
    .verdict/.summary/.success) y mitre_techniques (lista con .technique_id,
    .name, .tactic).
    """
    verdict = getattr(scan, "verdict", "unknown")
    color = _VERDICT_COLOR.get(verdict, _DEFAULT_COLOR)
    label = _VERDICT_LABEL.get(verdict, verdict.upper())

    pdf = _ReportPDF(scan.ioc_value)
    pdf.add_page()

    # --- Cabecera ---
    pdf.set_font("Helvetica", "B", 18)
    pdf.set_text_color(30, 41, 59)
    pdf.cell(0, 10, "Blue-Echo | Informe de IOC", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", size=9)
    pdf.set_text_color(120, 120, 120)
    created = getattr(scan, "created_at", None)
    if isinstance(created, datetime):
        created = created.strftime("%Y-%m-%d %H:%M UTC")
    pdf.cell(0, 6, _latin1(f"Generado: {created}"), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)

    # --- Banda de veredicto y score ---
    pdf.set_fill_color(*color)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 12, _latin1(f"  {label}   -   Score {scan.score}/100"),
             new_x="LMARGIN", new_y="NEXT", fill=True)
    pdf.ln(4)

    # --- Datos del IOC ---
    pdf.set_text_color(30, 41, 59)
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(28, 7, "Indicador:", new_x="RIGHT")
    pdf.set_font("Helvetica", size=10)
    pdf.multi_cell(0, 7, _latin1(scan.ioc_value), new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(28, 7, "Tipo:", new_x="RIGHT")
    pdf.set_font("Helvetica", size=10)
    pdf.cell(0, 7, _latin1(str(scan.ioc_type)), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)

    # --- Análisis de IA ---
    ai_summary = getattr(scan, "ai_summary", "") or ""
    if ai_summary.strip():
        _section_title(pdf, "Analisis del motor de IA")
        pdf.set_font("Helvetica", size=9)
        pdf.set_text_color(40, 40, 40)
        pdf.multi_cell(0, 5, _latin1(_strip_markdown(ai_summary)),
                       new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3)

    # --- Resultados por fuente ---
    results = getattr(scan, "connector_results", {}) or {}
    if results:
        _section_title(pdf, "Resultados por fuente")
        _results_table(pdf, results)
        pdf.ln(3)

    # --- MITRE ATT&CK ---
    mitre = getattr(scan, "mitre_techniques", []) or []
    if mitre:
        _section_title(pdf, "Tecnicas MITRE ATT&CK")
        pdf.set_font("Helvetica", size=9)
        pdf.set_text_color(40, 40, 40)
        for t in mitre:
            tid = getattr(t, "technique_id", "") or getattr(t, "id", "")
            name = getattr(t, "name", "")
            tactic = getattr(t, "tactic", "")
            line = f"- {tid} {name}" + (f"  ({tactic})" if tactic else "")
            pdf.multi_cell(0, 5, _latin1(line), new_x="LMARGIN", new_y="NEXT")

    out = pdf.output()
    return bytes(out)


def _section_title(pdf: FPDF, title: str) -> None:
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(37, 99, 235)
    pdf.cell(0, 8, _latin1(title), new_x="LMARGIN", new_y="NEXT")
    pdf.set_draw_color(37, 99, 235)
    pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
    pdf.ln(2)


def _results_table(pdf: FPDF, results: dict) -> None:
    # Cabecera de la tabla
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_fill_color(226, 232, 240)
    pdf.set_text_color(30, 41, 59)
    pdf.cell(38, 6, "Fuente", border=0, fill=True)
    pdf.cell(26, 6, "Veredicto", border=0, fill=True)
    pdf.cell(0, 6, "Resumen", border=0, fill=True, new_x="LMARGIN", new_y="NEXT")

    pdf.set_font("Helvetica", size=8)
    for name, r in sorted(results.items()):
        r_verdict = getattr(r, "verdict", "") or (r.get("verdict", "") if isinstance(r, dict) else "")
        r_summary = getattr(r, "summary", "") or (r.get("summary", "") if isinstance(r, dict) else "")
        vcolor = _VERDICT_COLOR.get(r_verdict, _DEFAULT_COLOR)

        y0 = pdf.get_y()
        pdf.set_text_color(30, 41, 59)
        pdf.cell(38, 6, _latin1(name), border="B")
        pdf.set_text_color(*vcolor)
        pdf.cell(26, 6, _latin1(_VERDICT_LABEL.get(r_verdict, r_verdict or "-")), border="B")
        pdf.set_text_color(60, 60, 60)
        pdf.multi_cell(0, 6, _latin1(r_summary or "-"), border="B",
                       new_x="LMARGIN", new_y="NEXT")
        # Evita solapamientos si multi_cell no avanzó de línea
        if pdf.get_y() <= y0:
            pdf.ln(6)
