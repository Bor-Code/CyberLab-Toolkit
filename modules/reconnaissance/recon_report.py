from datetime import datetime
from pathlib import Path

from app.banner import print_section_title
from core.finding import create_finding
from core.report_store import append_finding

from modules.reconnaissance.network_discovery import (
    load_network_devices,
    analyze_network_devices,
    summarize_network_devices,
    get_network_discovery_severity,
)

from modules.reconnaissance.dns_lookup import (
    load_dns_records,
    analyze_dns_records,
    summarize_dns_records,
    get_dns_lookup_severity,
)

from modules.reconnaissance.subdomain_simulator import (
    load_wordlist,
    load_simulated_subdomains,
    analyze_subdomain_words,
    summarize_subdomain_results,
    get_subdomain_severity,
    DEFAULT_BASE_DOMAIN,
)


RECON_REPORT_PATH = Path("reports/reconnaissance_report.md")


def ensure_reports_directory():
    RECON_REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)


def get_report_timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def collect_recon_data():
    network_devices = load_network_devices()
    network_results = analyze_network_devices(network_devices)
    network_summary = summarize_network_devices(network_results)

    dns_records = load_dns_records()
    dns_results = analyze_dns_records(dns_records)
    dns_summary = summarize_dns_records(dns_results)

    subdomain_words = load_wordlist()
    simulated_subdomains = load_simulated_subdomains()
    subdomain_results = analyze_subdomain_words(
        subdomain_words,
        simulated_subdomains,
        DEFAULT_BASE_DOMAIN,
    )
    subdomain_summary = summarize_subdomain_results(subdomain_results)

    return {
        "generated_at": get_report_timestamp(),
        "network_results": network_results,
        "network_summary": network_summary,
        "network_severity": get_network_discovery_severity(network_summary),
        "dns_results": dns_results,
        "dns_summary": dns_summary,
        "dns_severity": get_dns_lookup_severity(dns_summary),
        "subdomain_results": subdomain_results,
        "subdomain_summary": subdomain_summary,
        "subdomain_severity": get_subdomain_severity(subdomain_summary),
    }


def build_report_header(data):
    return [
        "# Reconnaissance Lab Report",
        "",
        f"Generated at: {data['generated_at']}",
        "",
        "## Safety Boundary",
        "",
        "- This report is generated from local sample files.",
        "- No real network scanning is performed.",
        "- No live DNS lookup is performed.",
        "- No subdomain enumeration against real domains is performed.",
        "- No packets are sent to external systems.",
        "- This report is for authorized learning and defensive documentation only.",
        "",
    ]


def build_network_section(data):
    summary = data["network_summary"]
    results = data["network_results"]
    lines = [
        "## Local Network Inventory Review",
        "",
        f"Severity estimate: `{data['network_severity']}`",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Total devices | {summary['total']} |",
        f"| Online devices | {summary['online']} |",
        f"| Offline devices | {summary['offline']} |",
        f"| Unknown device types | {summary['unknown_type']} |",
        f"| Devices needing review | {summary['needs_review']} |",
        "",
        "| IP | Hostname | Type | Status | Risk | Score |",
        "|---|---|---|---|---|---|",
    ]

    for result in results:
        lines.append(
            f"| {result['ip']} | {result['hostname']} | {result['device_type']} | "
            f"{result['status']} | {result['risk']} | {result['score']} |"
        )

    lines.extend(["", ""])

    return lines


def build_dns_section(data):
    summary = data["dns_summary"]
    results = data["dns_results"]
    lines = [
        "## Safe DNS Record Review",
        "",
        f"Severity estimate: `{data['dns_severity']}`",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Total records | {summary['total']} |",
        f"| Medium risk records | {summary['medium_risk']} |",
        f"| Low risk records | {summary['low_risk']} |",
        f"| Low TTL records | {summary['low_ttl_records']} |",
        f"| Keyword records | {summary['keyword_records']} |",
        "",
        "| Type | Name | Value | TTL | Risk | Score |",
        "|---|---|---|---|---|---|",
    ]

    for result in results:
        lines.append(
            f"| {result['record_type']} | {result['name']} | {result['value']} | "
            f"{result['ttl']} | {result['risk']} | {result['score']} |"
        )

    lines.extend(["", ""])

    return lines


def build_subdomain_section(data):
    summary = data["subdomain_summary"]
    results = data["subdomain_results"]
    lines = [
        "## Subdomain Wordlist Simulation",
        "",
        f"Base domain: `{DEFAULT_BASE_DOMAIN}`",
        "",
        f"Severity estimate: `{data['subdomain_severity']}`",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Total candidates | {summary['total']} |",
        f"| Simulated matches | {summary['simulated_matches']} |",
        f"| Simulated no matches | {summary['simulated_no_matches']} |",
        f"| High interest words | {summary['high_interest_words']} |",
        f"| Medium risk candidates | {summary['medium_risk']} |",
        f"| Low risk candidates | {summary['low_risk']} |",
        "",
        "| Word | Candidate | Simulated Status | Risk | Score |",
        "|---|---|---|---|---|",
    ]

    for result in results:
        lines.append(
            f"| {result['word']} | {result['candidate']} | {result['discovery_status']} | "
            f"{result['risk']} | {result['score']} |"
        )

    lines.extend(["", ""])

    return lines


def build_recommendations_section():
    return [
        "## Defensive Recommendations",
        "",
        "- Keep local network device inventories documented.",
        "- Review unknown hostnames, unknown vendors, and uncommon device types.",
        "- Review DNS records only for domains you own or are authorized to analyze.",
        "- Document low TTL DNS records and keyword-based DNS names.",
        "- Use subdomain wordlists only in authorized environments.",
        "- Separate simulated matches from generated candidates.",
        "- Do not scan, enumerate, or query real external systems without explicit permission.",
        "",
    ]


def build_recon_report(data):
    lines = []
    lines.extend(build_report_header(data))
    lines.extend(build_network_section(data))
    lines.extend(build_dns_section(data))
    lines.extend(build_subdomain_section(data))
    lines.extend(build_recommendations_section())

    return "\n".join(lines)


def write_recon_report(data):
    ensure_reports_directory()
    report_content = build_recon_report(data)
    RECON_REPORT_PATH.write_text(report_content, encoding="utf-8")
    return RECON_REPORT_PATH


def get_overall_recon_severity(data):
    severities = {
        data["network_severity"],
        data["dns_severity"],
        data["subdomain_severity"],
    }

    if "high" in severities:
        return "high"

    if "medium" in severities:
        return "medium"

    if "low" in severities:
        return "low"

    return "info"


def build_recon_report_evidence(data):
    return [
        f"Report path: {RECON_REPORT_PATH}",
        f"Generated at: {data['generated_at']}",
        f"Network devices reviewed: {data['network_summary']['total']}",
        f"DNS records reviewed: {data['dns_summary']['total']}",
        f"Subdomain candidates generated: {data['subdomain_summary']['total']}",
        f"Network severity: {data['network_severity']}",
        f"DNS severity: {data['dns_severity']}",
        f"Subdomain severity: {data['subdomain_severity']}",
    ]


def build_recon_report_recommendations():
    return [
        "Use this report only for authorized recon lab documentation.",
        "Review unknown devices and suspicious DNS patterns manually.",
        "Do not perform real scanning or live enumeration without permission.",
        "Store reports as local portfolio artifacts and lab evidence.",
    ]


def save_recon_report_finding(data):
    finding = create_finding(
        title="Reconnaissance lab report generated",
        description="A local reconnaissance report was generated from safe sample data.",
        severity=get_overall_recon_severity(data),
        category="reconnaissance",
        source_module="recon_report",
        mitre_technique="N/A",
        evidence=build_recon_report_evidence(data),
        recommendations=build_recon_report_recommendations(),
    )

    append_finding(finding)
    return finding


def print_report_summary(data, report_path):
    print("Reconnaissance report summary:")
    print(f"- Report path: {report_path}")
    print(f"- Generated at: {data['generated_at']}")
    print(f"- Network devices reviewed: {data['network_summary']['total']}")
    print(f"- DNS records reviewed: {data['dns_summary']['total']}")
    print(f"- Subdomain candidates generated: {data['subdomain_summary']['total']}")
    print(f"- Network severity: {data['network_severity']}")
    print(f"- DNS severity: {data['dns_severity']}")
    print(f"- Subdomain severity: {data['subdomain_severity']}")
    print(f"- Overall severity: {get_overall_recon_severity(data)}")


def run_recon_report():
    print_section_title("Save Recon Result")
    print("This module generates a local reconnaissance report from safe sample data.")
    print("It does not scan networks, perform live DNS lookups, or enumerate real domains.")
    print()

    data = collect_recon_data()
    report_path = write_recon_report(data)

    print_report_summary(data, report_path)
    print()

    answer = input("Save reconnaissance report generation as a local finding? (y/n): ").strip().lower()

    if answer == "y":
        save_recon_report_finding(data)
        print("Reconnaissance report finding saved to local findings store.")
    else:
        print("Reconnaissance report finding was not saved.")