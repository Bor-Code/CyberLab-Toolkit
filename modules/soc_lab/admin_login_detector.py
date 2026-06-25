from datetime import datetime

from app.banner import print_section_title
from core.finding import create_finding
from core.report_store import append_finding
from modules.soc_lab.auth_log_analyzer import (
    DEFAULT_AUTH_LOG_PATH,
    SUCCESS_EVENT,
    load_auth_logs,
)


PRIVILEGED_USERS = {
    "admin",
    "administrator",
    "root",
    "superuser",
}

TRUSTED_ADMIN_IPS = {
    "10.0.0.10",
}

BUSINESS_HOUR_START = 8
BUSINESS_HOUR_END = 18


def parse_event_hour(timestamp):
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        return parsed.hour
    except ValueError:
        return None


def is_privileged_user(username):
    return username.lower() in PRIVILEGED_USERS


def is_outside_business_hours(timestamp):
    hour = parse_event_hour(timestamp)

    if hour is None:
        return False

    return hour < BUSINESS_HOUR_START or hour >= BUSINESS_HOUR_END


def is_untrusted_admin_ip(ip_address):
    return ip_address not in TRUSTED_ADMIN_IPS


def detect_suspicious_admin_logins(events):
    detections = []

    for event in events:
        if event["event_type"] != SUCCESS_EVENT:
            continue

        username = event["user"]
        ip_address = event["ip"]

        if not is_privileged_user(username):
            continue

        reasons = []

        if is_untrusted_admin_ip(ip_address):
            reasons.append("Admin login from untrusted IP address")

        if is_outside_business_hours(event["timestamp"]):
            reasons.append("Admin login outside business hours")

        if reasons:
            detections.append(
                {
                    "timestamp": event["timestamp"],
                    "user": username,
                    "ip": ip_address,
                    "reasons": reasons,
                    "raw": event["raw"],
                }
            )

    return detections


def get_admin_detection_severity(detections):
    if not detections:
        return "info"

    outside_hours_count = 0
    untrusted_ip_count = 0

    for detection in detections:
        if "Admin login outside business hours" in detection["reasons"]:
            outside_hours_count += 1

        if "Admin login from untrusted IP address" in detection["reasons"]:
            untrusted_ip_count += 1

    if outside_hours_count >= 2 or untrusted_ip_count >= 2:
        return "high"

    return "medium"


def build_admin_detection_evidence(detections):
    evidence = []

    for detection in detections:
        reason_text = ", ".join(detection["reasons"])
        evidence.append(
            f"user={detection['user']} ip={detection['ip']} "
            f"timestamp={detection['timestamp']} reasons={reason_text}"
        )

    return evidence


def save_admin_login_finding(detections):
    if not detections:
        return None

    finding = create_finding(
        title="Suspicious privileged login detected",
        description="One or more privileged account logins were detected from suspicious conditions in local sample logs.",
        severity=get_admin_detection_severity(detections),
        category="soc_lab",
        source_module="admin_login_detector",
        mitre_technique="T1078",
        evidence=build_admin_detection_evidence(detections),
        recommendations=[
            "Review privileged account login activity.",
            "Verify whether the login source IP address is expected.",
            "Investigate privileged logins outside business hours.",
            "Require MFA for administrator accounts.",
            "Restrict administrator access to trusted networks or jump hosts.",
            "Create alerting for unusual privileged account activity.",
        ],
    )

    append_finding(finding)
    return finding


def print_admin_detections(detections):
    if not detections:
        print("No suspicious privileged login was detected.")
        return

    print("Suspicious privileged logins detected:")
    print()

    for index, detection in enumerate(detections, start=1):
        print(f"Detection {index}:")
        print(f"- Timestamp: {detection['timestamp']}")
        print(f"- User: {detection['user']}")
        print(f"- IP: {detection['ip']}")
        print(f"- Reasons: {', '.join(detection['reasons'])}")
        print()


def run_admin_login_detector():
    print_section_title("Detect Suspicious Admin Login")
    print("This module detects suspicious privileged logins in local sample logs.")
    print("It does not connect to real systems or perform authentication attempts.")
    print(f"Log source: {DEFAULT_AUTH_LOG_PATH}")
    print(f"Trusted admin IPs: {', '.join(sorted(TRUSTED_ADMIN_IPS))}")
    print(f"Business hours: {BUSINESS_HOUR_START}:00 - {BUSINESS_HOUR_END}:00 UTC")
    print()

    events = load_auth_logs()

    if not events:
        print("No authentication events were found.")
        return

    detections = detect_suspicious_admin_logins(events)

    print_admin_detections(detections)

    if detections:
        print(f"Severity estimate: {get_admin_detection_severity(detections)}")
        print()

    answer = input("Save suspicious admin login detection as a local finding? (y/n): ").strip().lower()

    if answer == "y":
        finding = save_admin_login_finding(detections)

        if finding:
            print("Suspicious admin login finding saved to local findings store.")
        else:
            print("No finding was saved because no detection was found.")
    else:
        print("Suspicious admin login finding was not saved.")