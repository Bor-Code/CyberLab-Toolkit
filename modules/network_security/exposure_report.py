from datetime import datetime
from pathlib import Path

from app.banner import print_section_title
from core.finding import create_finding
from core.report_store import append_finding
from modules.network_security.common_ports import (
    summarize_common_ports,
)
from modules.network_security.firewall_recommendation import (
    analyze_firewall_rules,
    load_firewall_rules_from_file,
    summarize_firewall_results,
)
from modules.network_security.localhost_check import (
    analyze_localhost_services,
    load_localhost_services_from_file,
    summarize_localhost_results,
)
from modules.network_security.port_checker import (
    analyze_port_observations,
    load_port_observations_from_file,
    summarize_port_results,
)


NETWORK_REPORT_PATH = Path("reports/network_exposure_report.md")


def ensure_reports_directory():
    NETWORK_REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)


def build_network_exposure_data():
    port_results = analyze_port_observations(load_port_observations_from_file())
    port_summary = summarize_port_results(port_results)

    localhost_results = analyze_localhost_services(load_localhost_services_from_file())
    localhost_summary = summarize_localhost_results(localhost_results)

    firewall_results = analyze_firewall_rules(load_firewall_rules_from_file())
    firewall_summary = summarize_firewall_results(firewall_results)

    common_port_summary = summarize_common_ports()

    return {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "port_results": port_results,
        "port_summary": port_summary,
        "localhost_results": localhost_results,
        "localhost_summary": localhost_summary,
        "firewall_results": firewall_results,
        "firewall_summary": firewall_summary,
        "common_port_summary": common_port_summary,
    }


def calculate_total_observations(report_data):
    return (
        report_data["port_summary"]["total"]
        + report_data["localhost_summary"]["total"]
        + report_data["firewall_summary"]["total"]
    )


def calculate_high_risk_items(report_data):
    return report_data["firewall_summary"]["high_risk"]


def calculate_medium_risk_items(report_data):
    return (
        report_data["port_summary"]["medium_risk"]
        + report_data["localhost_summary"]["medium_risk"]
        + report_data["firewall_summary"]["medium_risk"]
    )


def calculate_low_risk_items(report_data):
    return (
        report_data["port_summary"]["low_risk"]
        + report_data["localhost_summary"]["low_risk"]
        + report_data["firewall_summary"]["low_risk"]
    )


def get_network_exposure_severity(report_data):
    high_risk = calculate_high_risk_items(report_data)
    medium_risk = calculate_medium_risk_items(report_data)

    if high_risk >= 2:
        return "high"

    if high_risk == 1:
        return "medium"

    if medium_risk >= 3:
        return "medium"

    if medium_risk >= 1:
        return "low"

    if calculate_low_risk_items(report_data) >= 1:
        return "low"

    return "info"


def build_markdown_header(report_data):
    return [
        "# Network Exposure Report",
        "",
        f"Generated at: {report_data['generated_at']}",
        "",
        "This report summarizes local network security lab observations.",
        "",
        "Safety boundary: this report is generated from local sample files only. It does not scan hosts, connect to services, modify firewall settings, or touch real targets.",
        "",
    ]


def build_port_section(report_data):
    summary = report_data["port_summary"]

    return [
        "## Port Observation Summary",
        "",
        f"- Total observations: {summary['total']}",
        f"- Open ports: {summary['open']}",
        f"- Closed or filtered ports: {summary['closed_or_filtered']}",
        f"- Medium risk observations: {summary['medium_risk']}",
        f"- Low risk observations: {summary['low_risk']}",
        f"- Info risk observations: {summary['info_risk']}",
        "",
    ]


def build_localhost_section(report_data):
    summary = report_data["localhost_summary"]

    return [
        "## Localhost Service Summary",
        "",
        f"- Total observations: {summary['total']}",
        f"- Listening services: {summary['listening']}",
        f"- Not listening services: {summary['not_listening']}",
        f"- Medium risk observations: {summary['medium_risk']}",
        f"- Low risk observations: {summary['low_risk']}",
        f"- Info risk observations: {summary['info_risk']}",
        "",
    ]


def build_firewall_section(report_data):
    summary = report_data["firewall_summary"]

    return [
        "## Firewall Rule Summary",
        "",
        f"- Total rules: {summary['total']}",
        f"- Allow rules: {summary['allow']}",
        f"- Deny rules: {summary['deny']}",
        f"- Inbound rules: {summary['inbound']}",
        f"- Outbound rules: {summary['outbound']}",
        f"- High risk rules: {summary['high_risk']}",
        f"- Medium risk rules: {summary['medium_risk']}",
        f"- Low risk rules: {summary['low_risk']}",
        f"- Info risk rules: {summary['info_risk']}",
        "",
    ]


def build_common_ports_section(report_data):
    summary = report_data["common_port_summary"]

    return [
        "## Common Port Reference Summary",
        "",
        f"- Total common ports explained: {summary['total']}",
        f"- High risk examples: {summary['high']}",
        f"- Medium risk examples: {summary['medium']}",
        f"- Low risk examples: {summary['low']}",
        "",
    ]


def build_recommendation_section(report_data):
    lines = [
        "## Recommendations",
        "",
        "- Review open ports against authorized scope.",
        "- Document why each exposed service is required.",
        "- Stop local development services when they are no longer needed.",
        "- Restrict administrative and database services to trusted networks.",
        "- Avoid public exposure for SSH, RDP, SMB, database, cache, and admin services.",
        "- Use default-deny inbound firewall logic where possible.",
    ]

    if calculate_high_risk_items(report_data):
        lines.append("- Prioritize high-risk firewall rules that allow sensitive services from public sources.")

    if calculate_medium_risk_items(report_data):
        lines.append("- Review medium-risk services and confirm that they are intentionally exposed.")

    lines.append("")
    return lines


def build_markdown_report(report_data):
    lines = []
    lines.extend(build_markdown_header(report_data))
    lines.extend(build_port_section(report_data))
    lines.extend(build_localhost_section(report_data))
    lines.extend(build_firewall_section(report_data))
    lines.extend(build_common_ports_section(report_data))
    lines.extend(build_recommendation_section(report_data))

    return "\n".join(lines)


def write_network_exposure_report(report_data):
    ensure_reports_directory()
    markdown = build_markdown_report(report_data)
    NETWORK_REPORT_PATH.write_text(markdown, encoding="utf-8")
    return NETWORK_REPORT_PATH


def build_network_report_evidence(report_data):
    return [
        f"Generated at: {report_data['generated_at']}",
        f"Total network observations: {calculate_total_observations(report_data)}",
        f"Open port observations: {report_data['port_summary']['open']}",
        f"Local listening services: {report_data['localhost_summary']['listening']}",
        f"Firewall high risk rules: {report_data['firewall_summary']['high_risk']}",
        f"Firewall medium risk rules: {report_data['firewall_summary']['medium_risk']}",
        f"Common ports documented: {report_data['common_port_summary']['total']}",
        f"Report path: {NETWORK_REPORT_PATH}",
    ]


def build_network_report_recommendations(report_data):
    recommendations = [
        "Use this report as a local exposure review before making firewall or service changes.",
        "Validate whether each open service is required and documented.",
        "Restrict sensitive services to trusted networks or localhost where possible.",
        "Review firewall allow rules that expose sensitive services to public sources.",
    ]

    if calculate_high_risk_items(report_data):
        recommendations.append("Prioritize public sensitive-service allow rules for remediation.")

    if calculate_medium_risk_items(report_data):
        recommendations.append("Review medium-risk services and apply least-privilege network access.")

    return list(dict.fromkeys(recommendations))


def save_network_exposure_finding(report_data):
    finding = create_finding(
        title="Network exposure report generated",
        description="Local network security samples were summarized into a defensive exposure report.",
        severity=get_network_exposure_severity(report_data),
        category="network_security",
        source_module="exposure_report",
        mitre_technique="N/A",
        evidence=build_network_report_evidence(report_data),
        recommendations=build_network_report_recommendations(report_data),
    )

    append_finding(finding)
    return finding


def print_network_report_summary(report_data):
    print("Network exposure report summary:")
    print(f"- Generated at: {report_data['generated_at']}")
    print(f"- Total observations: {calculate_total_observations(report_data)}")
    print(f"- High risk items: {calculate_high_risk_items(report_data)}")
    print(f"- Medium risk items: {calculate_medium_risk_items(report_data)}")
    print(f"- Low risk items: {calculate_low_risk_items(report_data)}")
    print(f"- Severity estimate: {get_network_exposure_severity(report_data)}")
    print()
    print("Source summaries:")
    print(f"- Port observations: {report_data['port_summary']['total']}")
    print(f"- Localhost observations: {report_data['localhost_summary']['total']}")
    print(f"- Firewall rules: {report_data['firewall_summary']['total']}")
    print(f"- Common ports explained: {report_data['common_port_summary']['total']}")


def run_exposure_report():
    print_section_title("Network Exposure Report")
    print("This module builds a local network exposure report for defensive analysis.")
    print("It does not scan hosts, connect to services, modify firewall settings, or touch real targets.")
    print()

    report_data = build_network_exposure_data()
    report_path = write_network_exposure_report(report_data)

    print_network_report_summary(report_data)
    print()
    print(f"Network exposure report written to: {report_path}")
    print()

    answer = input("Save network exposure report as a local finding? (y/n): ").strip().lower()

    if answer == "y":
        save_network_exposure_finding(report_data)
        print("Network exposure report finding saved to local findings store.")
    else:
        print("Network exposure report finding was not saved.")