from collections import Counter
from pathlib import Path

from app.banner import print_section_title
from core.finding import create_finding
from core.report_store import append_finding


DEFAULT_AUTH_LOG_PATH = Path("samples/auth_logs.txt")
FAILED_EVENT = "AUTH_FAILED"
SUCCESS_EVENT = "AUTH_SUCCESS"


def parse_key_value_tokens(tokens):
    parsed = {}

    for token in tokens:
        if "=" not in token:
            continue

        key, value = token.split("=", 1)
        parsed[key.strip()] = value.strip()

    return parsed


def parse_auth_log_line(line):
    cleaned_line = line.strip()

    if not cleaned_line or cleaned_line.startswith("#"):
        return None

    parts = cleaned_line.split()

    if len(parts) < 2:
        return None

    timestamp = parts[0]
    event_type = parts[1]
    fields = parse_key_value_tokens(parts[2:])

    return {
        "timestamp": timestamp,
        "event_type": event_type,
        "user": fields.get("user", "unknown"),
        "ip": fields.get("ip", "unknown"),
        "reason": fields.get("reason", "unknown"),
        "raw": cleaned_line,
    }


def load_auth_logs(path=DEFAULT_AUTH_LOG_PATH):
    target = Path(path)

    if not target.exists():
        return []

    events = []

    for line in target.read_text(encoding="utf-8").splitlines():
        event = parse_auth_log_line(line)

        if event:
            events.append(event)

    return events


def count_events(events, event_type):
    return sum(1 for event in events if event["event_type"] == event_type)


def summarize_auth_logs(events):
    failed_events = [event for event in events if event["event_type"] == FAILED_EVENT]
    success_events = [event for event in events if event["event_type"] == SUCCESS_EVENT]

    failed_by_user = Counter(event["user"] for event in failed_events)
    failed_by_ip = Counter(event["ip"] for event in failed_events)
    success_by_user = Counter(event["user"] for event in success_events)
    success_by_ip = Counter(event["ip"] for event in success_events)

    return {
        "total_events": len(events),
        "total_failed": len(failed_events),
        "total_success": len(success_events),
        "failed_by_user": failed_by_user,
        "failed_by_ip": failed_by_ip,
        "success_by_user": success_by_user,
        "success_by_ip": success_by_ip,
        "unique_users": sorted({event["user"] for event in events}),
        "unique_ips": sorted({event["ip"] for event in events}),
    }


def print_counter(counter, title):
    print(title)

    if not counter:
        print("- None")
        return

    for key, value in counter.most_common():
        print(f"- {key}: {value}")


def get_highest_count(counter):
    if not counter:
        return 0

    return max(counter.values())


def is_suspicious_summary(summary):
    highest_failed_user = get_highest_count(summary["failed_by_user"])
    highest_failed_ip = get_highest_count(summary["failed_by_ip"])

    return (
        summary["total_failed"] >= 5
        or highest_failed_user >= 3
        or highest_failed_ip >= 3
    )


def get_summary_severity(summary):
    highest_failed_user = get_highest_count(summary["failed_by_user"])
    highest_failed_ip = get_highest_count(summary["failed_by_ip"])

    if summary["total_failed"] >= 10 or highest_failed_ip >= 6:
        return "high"

    if summary["total_failed"] >= 5 or highest_failed_user >= 3 or highest_failed_ip >= 3:
        return "medium"

    return "info"


def build_finding_evidence(summary):
    evidence = [
        f"Total authentication events: {summary['total_events']}",
        f"Failed authentication events: {summary['total_failed']}",
        f"Successful authentication events: {summary['total_success']}",
        f"Unique users observed: {len(summary['unique_users'])}",
        f"Unique IP addresses observed: {len(summary['unique_ips'])}",
    ]

    for user, count in summary["failed_by_user"].most_common(3):
        evidence.append(f"Failed logins for user {user}: {count}")

    for ip_address, count in summary["failed_by_ip"].most_common(3):
        evidence.append(f"Failed logins from IP {ip_address}: {count}")

    return evidence


def save_auth_log_finding(summary):
    finding = create_finding(
        title="Authentication log analysis summary",
        description="Sample authentication logs were analyzed and suspicious failed login patterns were summarized.",
        severity=get_summary_severity(summary),
        category="soc_lab",
        source_module="auth_log_analyzer",
        mitre_technique="T1110",
        evidence=build_finding_evidence(summary),
        recommendations=[
            "Review repeated failed login attempts by user and source IP.",
            "Enable multi-factor authentication for sensitive accounts.",
            "Apply login rate limiting or progressive delay controls.",
            "Monitor failed login spikes and suspicious authentication sources.",
            "Investigate successful logins that occur after repeated failures.",
        ],
    )

    append_finding(finding)
    return finding


def run_auth_log_analyzer():
    print_section_title("Analyze Sample Authentication Logs")
    print("This module analyzes local sample authentication logs for SOC practice.")
    print(f"Log source: {DEFAULT_AUTH_LOG_PATH}")
    print()

    events = load_auth_logs()

    if not events:
        print("No authentication log events were found.")
        print("Check the sample log file path and content.")
        return

    summary = summarize_auth_logs(events)

    print("Authentication summary:")
    print(f"- Total events: {summary['total_events']}")
    print(f"- Failed logins: {summary['total_failed']}")
    print(f"- Successful logins: {summary['total_success']}")
    print(f"- Unique users: {len(summary['unique_users'])}")
    print(f"- Unique IP addresses: {len(summary['unique_ips'])}")
    print()

    print_counter(summary["failed_by_user"], "Failed logins by user:")
    print()
    print_counter(summary["failed_by_ip"], "Failed logins by IP:")
    print()
    print_counter(summary["success_by_user"], "Successful logins by user:")
    print()

    if is_suspicious_summary(summary):
        print("SOC note: Suspicious authentication activity was observed.")
    else:
        print("SOC note: No obvious suspicious authentication pattern was observed.")

    print()
    answer = input("Save authentication analysis as a local finding? (y/n): ").strip().lower()

    if answer == "y":
        save_auth_log_finding(summary)
        print("Authentication analysis finding saved to local findings store.")
    else:
        print("Authentication analysis finding was not saved.")