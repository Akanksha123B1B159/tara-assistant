"""Traceability report exports (CSV / PDF)."""
import csv
import html
import io

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

NAVY = colors.HexColor("#1F3864")
RISK_COLORS = {"Critical": "#F4B6B6", "High": "#F9CBAA", "Medium": "#FFE699", "Low": "#D5E8D4", "Very low": "#E2F0D9"}


def _risk_key(label: str) -> str:
    return label.replace(" (preliminary)", "")


def to_csv(report: dict) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Asset", "Threat scenario", "Risk", "Control / requirement", "Requirement IDs", "Test link",
                "Threat status", "Rating status", "Mitigation status", "Sources", "Record type", "Project",
                "Details / assumptions", "Risk inputs", "Requirement drafts", "Matrix version"])
    project = report.get("project") or {}
    project_name = project.get("name", report.get("project_id", ""))
    w.writerow(["", "", "", "", "", "", "", "", "", "", "project", project_name,
                project.get("description", ""), "", "", report.get("risk_matrix_version", "")])
    for doc in report.get("documents", []):
        w.writerow(["", "", "", "", "", "", "", "", "", doc.get("document", ""), "document", project_name,
                    f"{doc.get('doc_type', '')}; version {doc.get('version', '')}; sha256 {doc.get('sha256', '')}",
                    "", "", report.get("risk_matrix_version", "")])
    for asset in report.get("assets", []):
        w.writerow([f"{asset['asset_id']} {asset['name']}", "", "", "", "", "", "", "", asset["status"],
                    " || ".join(asset.get("citations", [])), "asset", project_name,
                    f"{asset['type']}; interface {asset['interface']}; owner {asset.get('owner', '')}; "
                    f"{asset.get('description', '')}; properties {asset.get('properties', '')}",
                    "", "", report.get("risk_matrix_version", "")])
    for surface in report.get("attack_surfaces", []):
        w.writerow([", ".join(surface.get("assets", [])), f"{surface['interface']}: {surface['entry_point']}",
                    surface["evidence_status"], surface["derivation"], "", "", "", "", surface["status"],
                    " || ".join(surface.get("citations", [])), "attack_surface", project_name,
                    f"Exposure: {surface['exposure']}; trust boundary: {surface.get('trust_boundary', '')}; "
                    f"derivation: {surface['derivation']}",
                    "", "", report.get("risk_matrix_version", "")])
    for r in report["rows"]:
        draft_text = " || ".join(f"{d['id']}: {d['text']} [{d['status']}; {d['review_status']}; {d['citation']}]" for d in r["requirement_details"])
        w.writerow([r["asset"], r["threat"], r["risk"], "; ".join(r["controls"]), "; ".join(r["requirements"]), "; ".join(r["tests"]),
                    r["status"]["threat"], r["status"]["rating"], "/".join(r["status"]["mitigations"]), " || ".join(r["citations"]),
                    "traceability", project_name, f"{r['threat_description']} | Assumptions: {'; '.join(r['assumptions'])}",
                    str(r["risk_inputs"] or ""), draft_text, report.get("risk_matrix_version", "")])
    return buf.getvalue()


def to_pdf(report: dict, project_name: str) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=landscape(A4), leftMargin=14 * mm, rightMargin=14 * mm, topMargin=14 * mm, bottomMargin=14 * mm,
                            title="Cybersecurity traceability report")
    ss = getSampleStyleSheet()
    h = ParagraphStyle("h", parent=ss["Title"], textColor=NAVY, fontSize=18, alignment=0)
    cell = ParagraphStyle("c", parent=ss["BodyText"], fontSize=8, leading=10)
    head = ParagraphStyle("hd", parent=cell, textColor=colors.white, fontName="Helvetica-Bold")
    story = [Paragraph("Cybersecurity traceability report", h), Paragraph(f"Project: {html.escape(project_name)}", ss["BodyText"])]
    if report.get("project"):
        story.append(Paragraph(html.escape(report["project"].get("description", "")), ss["BodyText"]))
    story.append(Paragraph(
        f"Risk matrix version: {html.escape(report.get('risk_matrix_version', 'unknown'))} "
        "(illustrative pilot rules; not an official ISO/SAE formula)",
        ss["BodyText"],
    ))
    story.append(Spacer(1, 6))

    assets = report.get("assets", [])
    if assets:
        story.append(Paragraph("Asset inventory", ss["Heading2"]))
        asset_rows = [[Paragraph(x, head) for x in ["Asset ID", "Name", "Type", "Interface", "Review status", "Sources"]]]
        for asset in assets:
            asset_rows.append([Paragraph(html.escape(str(asset.get(key, ""))), cell) for key in ("asset_id", "name", "type", "interface", "status")] +
                              [Paragraph(html.escape(" | ".join(asset.get("citations", []))), cell)])
        asset_table = Table(asset_rows, colWidths=[22 * mm, 43 * mm, 34 * mm, 27 * mm, 31 * mm, 109 * mm], repeatRows=1)
        asset_table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), NAVY), ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CCCCCC")), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        story += [asset_table, Spacer(1, 8)]
        story += [Paragraph(
            f"{html.escape(asset['asset_id'])} details: {html.escape(asset.get('description', ''))} "
            f"Owner: {html.escape(asset.get('owner', ''))}; properties: {html.escape(asset.get('properties', ''))}",
            cell,
        ) for asset in assets]

    surfaces = report.get("attack_surfaces", [])
    if surfaces:
        story.append(Paragraph("Attack-surface inventory (rule-based inferences)", ss["Heading2"]))
        surface_rows = [[Paragraph(x, head) for x in ["Interface", "Entry point", "Exposure", "Linked assets", "Evidence status", "Sources"]]]
        for surface in surfaces:
            values = [surface.get("interface", ""), surface.get("entry_point", ""), surface.get("exposure", ""),
                      ", ".join(surface.get("assets", [])), surface.get("evidence_status", ""),
                      " | ".join(surface.get("citations", []))]
            surface_rows.append([Paragraph(html.escape(str(value)), cell) for value in values])
        surface_table = Table(surface_rows, colWidths=[28 * mm, 55 * mm, 36 * mm, 45 * mm, 42 * mm, 60 * mm], repeatRows=1)
        surface_table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), NAVY), ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CCCCCC")), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        story += [surface_table, Spacer(1, 8)]
        story += [Paragraph(
            f"{html.escape(surface['interface'])} / {html.escape(surface['entry_point'])}: "
            f"{html.escape(surface['derivation'])}; trust boundary: {html.escape(surface.get('trust_boundary', ''))}",
            cell,
        ) for surface in surfaces]

    data = [[Paragraph(x, head) for x in ["Asset", "Threat scenario", "Risk", "Control / requirement", "Test link", "Status"]]]
    style = [("BACKGROUND", (0, 0), (-1, 0), NAVY), ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CCCCCC")), ("VALIGN", (0, 0), (-1, -1), "TOP")]
    for i, r in enumerate(report["rows"], 1):
        data.append([Paragraph(html.escape(r["asset"]), cell), Paragraph(html.escape(r["threat"]), cell), Paragraph(html.escape(r["risk"]), cell),
                     Paragraph("<br/>".join(html.escape(x) for x in r["controls"]) or "-", cell), Paragraph(html.escape(", ".join(r["tests"])) or "-", cell),
                     Paragraph(f"threat: {html.escape(r['status']['threat'])}<br/>rating: {html.escape(r['status']['rating'])}", cell)])
        style.append(("BACKGROUND", (2, i), (2, i), colors.HexColor(RISK_COLORS.get(_risk_key(r["risk"]), "#FFFFFF"))))
    t = Table(data, colWidths=[48 * mm, 62 * mm, 24 * mm, 70 * mm, 32 * mm, 30 * mm], repeatRows=1)
    t.setStyle(TableStyle(style))
    story += [t, Spacer(1, 10)]
    for r in report["rows"]:
        story.append(Spacer(1, 6))
        story.append(Paragraph(f"Scenario details: {html.escape(r['threat'])}", ss["Heading3"]))
        story.append(Paragraph(f"Description: {html.escape(r['threat_description'])}", cell))
        story.append(Paragraph(f"Assumptions: {html.escape('; '.join(r['assumptions']))}", cell))
        if r["risk_inputs"]:
            story.append(Paragraph(f"Impact and attack-potential inputs: {html.escape(str(r['risk_inputs']))}", cell))
        for draft in r["requirement_details"]:
            story.append(Paragraph(
                f"{html.escape(draft['id'])} ({html.escape(draft['status'])}; review: {html.escape(draft['review_status'])}): "
                f"{html.escape(draft['text'])} Source: {html.escape(draft['citation'])}",
                cell,
            ))
    if report["gaps"]:
        story.append(Paragraph("<b>Coverage gaps</b>", ss["BodyText"]))
        story += [Paragraph(f"- {html.escape(g)}", cell) for g in report["gaps"]]
        story.append(Spacer(1, 8))
    gov = Table([[Paragraph(f"<b>Governance principle</b><br/>{report['governance_principle']}", ss["BodyText"])]], colWidths=[240 * mm])
    gov.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FFF2CC")), ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor("#D6B656")),
                             ("LEFTPADDING", (0, 0), (-1, -1), 8), ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
    story.append(gov)
    doc.build(story)
    return buf.getvalue()
