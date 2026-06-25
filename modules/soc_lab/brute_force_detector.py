from collections import defaultdict
from pathlib import Path

from app.banner import print_section_title
from core.finding import create_finding
from core.report_store import append_finding
from modules.soc_lab.auth_log_analyzer import (
    DEFAULT_AUTH_LOG_PATH,
    FAILED_EVENT,
    load_auth_logs,
)


FAILED_THRESHOLD = 3


def group_failed_events(events):
    grouped_by_ip = defaultdict(list)
    grouped_by_user = defaultdict(list)

    for event in events:
        if event["event_type"] != FAILED_EVENT:
            continue

        grouped_by_ip[event["ip"]].append(event)
        grouped_by_user[event["user"]].append(event)

    return grouped_by_ip, grouped_by_user


def detect_brute_force_patterns(events, threshold=FAILED_THRESHOLD):
    grouped_by_ip, grouped_by_user = group_failed_events(events)
    detections = []

    for ip_address, failed_events in grouped_by_ip.items():
        if len(failed_events) >= threshold:
            users = sorted({event["user"] for event in failed_events})

            detections.append(
                {
                    "type": "source_ip",
                    "indicator": ip_address,
                    "failed_count": len(failed_events),
                    "related_users": users,
                    "first_seen": failed_events[0]["timestamp"],
                    "last_seen": failed_events[-1]["timestamp"],
                }
            )

    for username, failed_events in grouped_by_user.items():
        if len(failed_events) >= threshold:
            ips = sorted({event["ip"] for event in failed_events})

            detections.append(
                {
                    "type": "username",
                    "indicator": username,
                    "failed_count": len(failed_events),
                    "related_ips": ips,
                    "first_seen": failed_events[0]["timestamp"],
                    "last_seen": failed_events[-1]["timestamp"],
                }
            )

    return detections


def get_detection_severity(detections):
    if not detections:
        return "info"

    highest_failed_count = max(detection["failed_count"] for detection in detections)

    if highest_failed_count >= 8:
        return "high"

    if highest_failed_count >= 5:
        return "medium"

    return "low"


def format_detection(detection):
    lines = [
        f"Type: {detection['type']}",
        f"Indicator: {detection['indicator']}",
        f"Failed attempts: {detection['failed_count']}",
        f"First seen: {detection['first_seen']}",
        f"Last seen: {detection['last_seen']}",
    ]

    if detection["type"] == "source_ip":
        lines.append(f"Related users: {', '.join(detection['related_users'])}")

    if detection["type"] == "username":
        lines.append(f"Related IPs: {', '.join(detection['related_ips'])}")

    return lines


def build_detection_evidence(detections):
    evidence = []

    for detection in detections:
        evidence.append(
            f"{detection['type']}={detection['indicator']} failed_attempts={detection['failed_count']} "
            f"first_seen={detection['first_seen']} last_seen={detection['last_seen']}"
        )

    return evidence


def save_brute_force_finding(detections):
    if not detections:
        return None

    finding = create_finding(
        title="Possible brute-force authentication pattern detected",
        description="Repeated failed authentication attempts were detected in local sample authentication logs.",
        severity=get_detection_severity(detections),
        category="soc_lab",
        source_module="brute_force_detector",
        mitre_technique="T1110",
        evidence=build_detection_evidence(detections),
        recommendations=[
            "Review the source IP addresses and affected user accounts.",
            "Check whether successful logins occurred after repeated failures.",
            "Enable MFA for sensitive accounts.",
            "Apply login rate limiting or progressive delay controls.",
            "Create alerting for repeated failed authentication attempts.",
            "Review firewall or access control policies for suspicious sources.",
        ],
    )

    append_finding(finding)
    return finding


def print_detections(detections):
    if not detections:
        print("No brute-force pattern was detected.")
        return

    print("Possible brute-force patterns detected:")
    print()

    for index, detection in enumerate(detections, start=1):
        print(f"Detection {index}:")
        for line in format_detection(detection):
            print(f"- {line}")
        print()


def run_brute_force_detector():
    print_section_title("Detect Brute Force Pattern")
    print("This module detects repeated failed login patterns in local sample logs.")
    print("It does not perform login attempts or attack any service.")
    print(f"Log source: {Path(DEFAULT_AUTH_LOG_PATH)}")
    print(f"Failed attempt threshold: {FAILED_THRESHOLD}")
    print()

    events = load_auth_logs()

    if not events:
        print("No authentication events were found.")
        print("Run the authentication log analyzer setup or check the sample log file.")
        return

    detections = detect_brute_force_patterns(events)

    print_detections(detections)

    if detections:
        print(f"Severity estimate: {get_detection_severity(detections)}")
        print()

    answer = input("Save brute-force detection as a local finding? (y/n): ").strip().lower()

    if answer == "y":
        finding = save_brute_force_finding(detections)

        if finding:
            print("Brute-force detection finding saved to local findings store.")
        else:
            print("No finding was saved because no detection was found.")
    else:
        print("Brute-force detection finding was not saved.")