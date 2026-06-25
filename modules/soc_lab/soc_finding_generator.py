from app.banner import print_section_title
from core.finding import create_finding
from core.report_store import append_finding
from modules.soc_lab.admin_login_detector import detect_suspicious_admin_logins
from modules.soc_lab.auth_log_analyzer import load_auth_logs, summarize_auth_logs
from modules.soc_lab.brute_force_detector import detect_brute_force_patterns
from modules.soc_lab.repeated_404_detector import (
    detect_repeated_404_patterns,
    load_web_logs,
    summarize_web_logs,
)


def get_soc_summary_severity(auth_summary, brute_force_detections, admin_detections, repeated_404_detections):
    if admin_detections:
        return "high"

    if brute_force_detections and repeated_404_detections:
        return "high"

    if brute_force_detections or repeated_404_detections:
        return "medium"

    if auth_summary["total_failed"] >= 5:
        return "medium"

    return "info"


def build_soc_evidence(auth_summary, web_summary, brute_force_detections, admin_detections, repeated_404_detections):
    evidence = [
        f"Authentication events analyzed: {auth_summary['total_events']}",
        f"Failed authentication events: {auth_summary['total_failed']}",
        f"Successful authentication events: {auth_summary['total_success']}",
        f"Unique authentication users: {len(auth_summary['unique_users'])}",
        f"Unique authentication IPs: {len(auth_summary['unique_ips'])}",
        f"Web events analyzed: {web_summary['total_events']}",
        f"Web 404 responses: {web_summary['total_404']}",
        f"Brute-force detections: {len(brute_force_detections)}",
        f"Suspicious admin login detections: {len(admin_detections)}",
        f"Repeated 404 detections: {len(repeated_404_detections)}",
    ]

    for detection in brute_force_detections[:3]:
        evidence.append(
            f"Brute-force indicator: type={detection['type']} indicator={detection['indicator']} "
            f"failed_attempts={detection['failed_count']}"
        )

    for detection in admin_detections[:3]:
        evidence.append(
            f"Suspicious admin login: user={detection['user']} ip={detection['ip']} "
            f"timestamp={detection['timestamp']} reasons={', '.join(detection['reasons'])}"
        )

    for detection in repeated_404_detections[:3]:
        evidence.append(
            f"Repeated 404 indicator: ip={detection['ip']} count={detection['count']} "
            f"first_seen={detection['first_seen']} last_seen={detection['last_seen']}"
        )

    return evidence


def build_soc_recommendations(brute_force_detections, admin_detections, repeated_404_detections):
    recommendations = [
        "Review authentication and web log findings together for correlated activity.",
        "Validate all detections manually before taking action.",
        "Create alert rules for repeated failed logins and repeated 404 spikes.",
        "Use MFA for privileged and sensitive accounts.",
        "Apply rate limiting, account lockout, or progressive delay controls.",
        "Keep generated findings and reports as local lab artifacts unless intentionally published.",
    ]

    if brute_force_detections:
        recommendations.extend(
            [
                "Investigate source IPs and usernames involved in repeated failed authentication attempts.",
                "Check whether successful logins occurred after repeated failures.",
            ]
        )

    if admin_detections:
        recommendations.extend(
            [
                "Review privileged login events from untrusted IP addresses.",
                "Restrict administrator access to trusted networks or jump hosts.",
            ]
        )

    if repeated_404_detections:
        recommendations.extend(
            [
                "Review requested 404 paths for sensitive files, admin panels, or scanning behavior.",
                "Harden exposed web applications and monitor unusual web path discovery patterns.",
            ]
        )

    return list(dict.fromkeys(recommendations))


def generate_soc_finding():
    auth_events = load_auth_logs()
    web_events = load_web_logs()

    auth_summary = summarize_auth_logs(auth_events)
    web_summary = summarize_web_logs(web_events)

    brute_force_detections = detect_brute_force_patterns(auth_events)
    admin_detections = detect_suspicious_admin_logins(auth_events)
    repeated_404_detections = detect_repeated_404_patterns(web_events)

    severity = get_soc_summary_severity(
        auth_summary,
        brute_force_detections,
        admin_detections,
        repeated_404_detections,
    )

    finding = create_finding(
        title="SOC lab correlated detection summary",
        description="Local sample authentication and web logs were analyzed to generate a SOC-style correlated finding summary.",
        severity=severity,
        category="soc_lab",
        source_module="soc_finding_generator",
        mitre_technique="T1110, T1078, T1595",
        evidence=build_soc_evidence(
            auth_summary,
            web_summary,
            brute_force_detections,
            admin_detections,
            repeated_404_detections,
        ),
        recommendations=build_soc_recommendations(
            brute_force_detections,
            admin_detections,
            repeated_404_detections,
        ),
    )

    append_finding(finding)

    return finding, {
        "auth_events": len(auth_events),
        "web_events": len(web_events),
        "brute_force_detections": len(brute_force_detections),
        "admin_detections": len(admin_detections),
        "repeated_404_detections": len(repeated_404_detections),
        "severity": severity,
    }


def print_soc_generation_summary(summary):
    print("SOC finding generation summary:")
    print(f"- Authentication events analyzed: {summary['auth_events']}")
    print(f"- Web events analyzed: {summary['web_events']}")
    print(f"- Brute-force detections: {summary['brute_force_detections']}")
    print(f"- Suspicious admin login detections: {summary['admin_detections']}")
    print(f"- Repeated 404 detections: {summary['repeated_404_detections']}")
    print(f"- Generated severity: {summary['severity']}")


def run_soc_finding_generator():
    print_section_title("Generate SOC Finding")
    print("This module generates a SOC-style finding from local sample lab logs.")
    print("It does not connect to real systems, scan targets, or perform attacks.")
    print()

    answer = input("Generate and save SOC finding from sample logs? (y/n): ").strip().lower()

    if answer != "y":
        print("SOC finding generation cancelled.")
        return

    finding, summary = generate_soc_finding()

    print()
    print_soc_generation_summary(summary)
    print()
    print("SOC finding saved to local findings store.")
    print(f"Finding ID: {finding.finding_id}")