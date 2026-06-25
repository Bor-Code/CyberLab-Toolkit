from datetime import datetime
from pathlib import Path

from app.banner import print_section_title
from core.finding import create_finding
from core.report_store import append_finding
from modules.threat_intel.domain_classifier import (
    analyze_domain_indicators,
    load_domain_indicators_from_file,
    summarize_domain_results,
)
from modules.threat_intel.hash_classifier import (
    analyze_hash_indicators,
    load_hash_indicators_from_file,
    summarize_hash_results,
)
from modules.threat_intel.ioc_format_checker import (
    analyze_ioc_formats,
    load_iocs_from_file,
    summarize_ioc_formats,
)
from modules.threat_intel.ip_classifier import (
    analyze_ip_indicators,
    load_ip_indicators_from_file,
    summarize_ip_results,
)


IOC_REPORT_PATH = Path("reports/ioc_summary_report.md")


def ensure_reports_directory():
    IOC_REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)


def build_ioc_report_data():
    ioc_format_results = analyze_ioc_formats(load_iocs_from_file())
    ioc_format_summary = summarize_ioc_formats(ioc_format_results)

    ip_results = analyze_ip_indicators(load_ip_indicators_from_file())
    ip_summary = summarize_ip_results(ip_results)

    domain_results = analyze_domain_indicators(load_domain_indicators_from_file())
    domain_summary = summarize_domain_results(domain_results)

    hash_results = analyze_hash_indicators(load_hash_indicators_from_file())
    hash_summary = summarize_hash_results(hash_results)

    return {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ioc_format_results": ioc_format_results,
        "ioc_format_summary": ioc_format_summary,
        "ip_results": ip_results,
        "ip_summary": ip_summary,
        "domain_results": domain_results,
        "domain_summary": domain_summary,
        "hash_results": hash_results,
        "hash_summary": hash_summary,
    }


def calculate_total_indicators(report_data):
    return (
        report_data["ioc_format_summary"]["total"]
        + report_data["ip_summary"]["total"]
        + report_data["domain_summary"]["total"]
        + report_data["hash_summary"]["total"]
    )


def calculate_total_invalid(report_data):
    return (
        report_data["ioc_format_summary"]["unknown"]
        + report_data["ip_summary"]["invalid"]
        + report_data["domain_summary"]["invalid"]
        + report_data["hash_summary"]["invalid"]
    )


def calculate_total_medium_risk(report_data):
    return (
        report_data["domain_summary"]["medium_risk"]
        + report_data["hash_summary"].get("weak_hash_format", 0)
    )


def get_ioc_report_severity(report_data):
    total_invalid = calculate_total_invalid(report_data)
    total_medium_risk = calculate_total_medium_risk(report_data)

    if total_invalid >= 6:
        return "medium"

    if total_medium_risk >= 3:
        return "medium"

    if total_invalid >= 1:
        return "low"

    return "info"


def build_markdown_header(report_data):
    return [
        "# IOC Summary Report",
        "",
        f"Generated at: {report_data['generated_at']}",
        "",
        "This report summarizes local IOC format, IP, domain, and hash indicator analysis.",
        "",
        "Safety boundary: this report is generated from local sample files only. It does not query external APIs, scan targets, download files, or execute samples.",
        "",
    ]


def build_format_section(report_data):
    summary = report_data["ioc_format_summary"]
    lines = [
        "## IOC Format Summary",
        "",
        f"- Total indicators: {summary['total']}",
        f"- Valid indicators: {summary['valid']}",
        f"- Unknown indicators: {summary['unknown']}",
        "",
        "| Type | Count |",
        "|---|---:|",
    ]

    for indicator_type, count in summary["types"].items():
        lines.append(f"| {indicator_type} | {count} |")

    lines.append("")
    return lines


def build_ip_section(report_data):
    summary = report_data["ip_summary"]
    lines = [
        "## IP Indicator Summary",
        "",
        f"- Total: {summary['total']}",
        f"- Valid: {summary['valid']}",
        f"- Invalid: {summary['invalid']}",
        f"- Public: {summary['public']}",
        f"- Private: {summary['private']}",
        f"- Loopback: {summary['loopback']}",
        f"- Link-local: {summary['link-local']}",
        f"- Multicast: {summary['multicast']}",
        f"- Reserved: {summary['reserved']}",
        f"- Unspecified: {summary['unspecified']}",
        "",
    ]

    return lines


def build_domain_section(report_data):
    summary = report_data["domain_summary"]
    lines = [
        "## Domain Indicator Summary",
        "",
        f"- Total: {summary['total']}",
        f"- Valid: {summary['valid']}",
        f"- Invalid or non-domain: {summary['invalid']}",
        f"- Public domains: {summary['public-domain']}",
        f"- Internal or local domains: {summary['internal-or-local']}",
        f"- Punycode domains: {summary['punycode-domain']}",
        f"- IP-address values: {summary['ip-address']}",
        f"- Medium risk: {summary['medium_risk']}",
        f"- Low risk: {summary['low_risk']}",
        f"- Info risk: {summary['info_risk']}",
        "",
    ]

    return lines


def build_hash_section(report_data):
    summary = report_data["hash_summary"]
    lines = [
        "## Hash Indicator Summary",
        "",
        f"- Total: {summary['total']}",
        f"- Valid: {summary['valid']}",
        f"- Invalid: {summary['invalid']}",
        f"- MD5: {summary['MD5']}",
        f"- SHA1: {summary['SHA1']}",
        f"- SHA256: {summary['SHA256']}",
        f"- SHA512: {summary['SHA512']}",
        f"- Weak hash format: {summary['weak_hash_format']}",
        f"- Non-hex values: {summary['non_hex']}",
        "",
    ]

    return lines


def build_recommendation_section(report_data):
    total_invalid = calculate_total_invalid(report_data)

    lines = [
        "## Recommendations",
        "",
        "- Validate IOC format before enrichment, alerting, reporting, or blocking.",
        "- Separate IP, domain, URL, and hash indicators before deeper analysis.",
        "- Review private, loopback, internal, local, malformed, and unsupported indicators manually.",
        "- Prefer SHA256 hashes for modern malware and file reputation workflows when possible.",
    ]

    if total_invalid:
        lines.append("- Clean malformed or unsupported indicators before sharing the IOC list.")

    lines.append("")
    return lines


def build_markdown_report(report_data):
    lines = []
    lines.extend(build_markdown_header(report_data))
    lines.extend(build_format_section(report_data))
    lines.extend(build_ip_section(report_data))
    lines.extend(build_domain_section(report_data))
    lines.extend(build_hash_section(report_data))
    lines.extend(build_recommendation_section(report_data))

    return "\n".join(lines)


def write_ioc_report(report_data):
    ensure_reports_directory()
    markdown = build_markdown_report(report_data)
    IOC_REPORT_PATH.write_text(markdown, encoding="utf-8")
    return IOC_REPORT_PATH


def build_ioc_report_evidence(report_data):
    return [
        f"Generated at: {report_data['generated_at']}",
        f"Total indicators across sample sets: {calculate_total_indicators(report_data)}",
        f"Unknown IOC format values: {report_data['ioc_format_summary']['unknown']}",
        f"Invalid IP indicators: {report_data['ip_summary']['invalid']}",
        f"Invalid domain indicators: {report_data['domain_summary']['invalid']}",
        f"Invalid hash indicators: {report_data['hash_summary']['invalid']}",
        f"Punycode domains: {report_data['domain_summary']['punycode-domain']}",
        f"Weak hash formats: {report_data['hash_summary']['weak_hash_format']}",
        f"Report path: {IOC_REPORT_PATH}",
    ]


def build_ioc_report_recommendations(report_data):
    recommendations = [
        "Use this IOC report as a local triage summary before enrichment or operational action.",
        "Validate malformed or unknown indicators before sharing or importing into security tools.",
        "Keep public IPs, private IPs, domains, URLs, and hashes in separate analysis groups.",
        "Use authorized enrichment tools only after IOC format and context are verified.",
    ]

    if calculate_total_invalid(report_data):
        recommendations.append("Clean invalid IOC values before using the list in detections or reports.")

    return recommendations


def save_ioc_report_finding(report_data):
    finding = create_finding(
        title="IOC summary report generated",
        description="Local IOC samples were analyzed and summarized into a defensive threat intelligence report.",
        severity=get_ioc_report_severity(report_data),
        category="threat_intel",
        source_module="ioc_report_builder",
        mitre_technique="N/A",
        evidence=build_ioc_report_evidence(report_data),
        recommendations=build_ioc_report_recommendations(report_data),
    )

    append_finding(finding)
    return finding


def print_ioc_report_summary(report_data):
    print("IOC report summary:")
    print(f"- Generated at: {report_data['generated_at']}")
    print(f"- Total indicators across sample sets: {calculate_total_indicators(report_data)}")
    print(f"- Total invalid or unknown indicators: {calculate_total_invalid(report_data)}")
    print(f"- Severity estimate: {get_ioc_report_severity(report_data)}")
    print()
    print("Source summaries:")
    print(f"- IOC format total: {report_data['ioc_format_summary']['total']}")
    print(f"- IP total: {report_data['ip_summary']['total']}")
    print(f"- Domain total: {report_data['domain_summary']['total']}")
    print(f"- Hash total: {report_data['hash_summary']['total']}")


def run_ioc_report_builder():
    print_section_title("IOC Report Builder")
    print("This module builds a local IOC summary report for defensive analysis.")
    print("It does not query external APIs, scan targets, download files, or execute samples.")
    print()

    report_data = build_ioc_report_data()
    report_path = write_ioc_report(report_data)
    print_ioc_report_summary(report_data)
    print()
    print(f"IOC summary report written to: {report_path}")
    print()

    answer = input("Save IOC report generation as a local finding? (y/n): ").strip().lower()

    if answer == "y":
        save_ioc_report_finding(report_data)
        print("IOC report finding saved to local findings store.")
    else:
        print("IOC report finding was not saved.")