from pathlib import Path

from app.banner import print_section_title
from core.constants import DEFAULT_FINDINGS_PATH, DEFAULT_REPORT_PATH
from core.report_store import load_findings
from core.risk_score import calculate_finding_score, summarize_risk


def format_list(items):
    if not items:
        return "- None"

    lines = []

    for item in items:
        lines.append(f"- {item}")

    return "\n".join(lines)


def format_finding_section(finding, index):
    score = calculate_finding_score(finding)

    lines = [
        f"## Finding {index}: {finding.title}",
        "",
        f"| Field | Value |",
        f"|---|---|",
        f"| Finding ID | `{finding.finding_id}` |",
        f"| Timestamp | `{finding.timestamp}` |",
        f"| Severity | `{finding.severity}` |",
        f"| Risk Score | `{score}/100` |",
        f"| Category | `{finding.category}` |",
        f"| Source Module | `{finding.source_module}` |",
        f"| MITRE Technique | `{finding.mitre_technique}` |",
        "",
        "### Description",
        "",
        finding.description or "No description provided.",
        "",
        "### Evidence",
        "",
        format_list(finding.evidence),
        "",
        "### Recommendations",
        "",
        format_list(finding.recommendations),
        "",
    ]

    return "\n".join(lines)


def build_markdown_report(findings):
    summary = summarize_risk(findings)

    lines = [
        "# CyberLab Toolkit Report",
        "",
        "This report was generated from local educational lab findings.",
        "",
        "## Safety Notice",
        "",
        "CyberLab Toolkit is designed for cybersecurity education, authorized lab testing, and defensive learning only.",
        "",
        "This report does not prove compromise by itself. Findings should be reviewed by an analyst in context.",
        "",
        "## Executive Summary",
        "",
        f"- Total findings: {summary['total_findings']}",
        f"- Highest score: {summary['highest_score']}/100",
        f"- Highest level: {summary['highest_level']}",
        f"- Average score: {summary['average_score']}/100",
        "",
    ]

    if not findings:
        lines.extend(
            [
                "## Findings",
                "",
                "No findings were found in the local findings store.",
                "",
            ]
        )
        return "\n".join(lines)

    lines.extend(
        [
            "## Findings",
            "",
        ]
    )

    for index, finding in enumerate(findings, start=1):
        lines.append(format_finding_section(finding, index))

    lines.extend(
        [
            "## Defensive Follow-Up",
            "",
            "- Validate findings manually before taking action.",
            "- Prioritize high and critical severity findings.",
            "- Review evidence and source module context.",
            "- Apply defensive recommendations where appropriate.",
            "- Re-run relevant lab modules after remediation.",
            "",
        ]
    )

    return "\n".join(lines)


def write_markdown_report(findings_path=DEFAULT_FINDINGS_PATH, report_path=DEFAULT_REPORT_PATH):
    findings = load_findings(findings_path)
    report_content = build_markdown_report(findings)

    target = Path(report_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(report_content, encoding="utf-8")

    return target, len(findings)


def run_markdown_report():
    print_section_title("Generate Markdown Report")
    print("This module generates a Markdown report from local lab findings.")
    print(f"Findings source: {DEFAULT_FINDINGS_PATH}")
    print(f"Report output: {DEFAULT_REPORT_PATH}")
    print()

    report_path, finding_count = write_markdown_report()

    print("Markdown report generated successfully.")
    print(f"Findings included: {finding_count}")
    print(f"Report path: {report_path}")