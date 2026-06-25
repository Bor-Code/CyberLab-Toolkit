from collections import Counter, defaultdict
from pathlib import Path

from app.banner import print_section_title
from core.finding import create_finding
from core.report_store import append_finding


DEFAULT_WEB_LOG_PATH = Path("samples/web_logs.txt")
NOT_FOUND_STATUS = "404"
REPEATED_404_THRESHOLD = 3


def parse_web_log_line(line):
    cleaned_line = line.strip()

    if not cleaned_line or cleaned_line.startswith("#"):
        return None

    parts = cleaned_line.split()

    if len(parts) < 5:
        return None

    return {
        "timestamp": parts[0],
        "ip": parts[1],
        "method": parts[2],
        "path": parts[3],
        "status": parts[4],
        "raw": cleaned_line,
    }


def load_web_logs(path=DEFAULT_WEB_LOG_PATH):
    target = Path(path)

    if not target.exists():
        return []

    events = []

    for line in target.read_text(encoding="utf-8").splitlines():
        event = parse_web_log_line(line)

        if event:
            events.append(event)

    return events


def group_404_events_by_ip(events):
    grouped = defaultdict(list)

    for event in events:
        if event["status"] == NOT_FOUND_STATUS:
            grouped[event["ip"]].append(event)

    return grouped


def detect_repeated_404_patterns(events, threshold=REPEATED_404_THRESHOLD):
    grouped = group_404_events_by_ip(events)
    detections = []

    for ip_address, not_found_events in grouped.items():
        if len(not_found_events) < threshold:
            continue

        requested_paths = [event["path"] for event in not_found_events]

        detections.append(
            {
                "ip": ip_address,
                "count": len(not_found_events),
                "first_seen": not_found_events[0]["timestamp"],
                "last_seen": not_found_events[-1]["timestamp"],
                "paths": requested_paths,
                "top_paths": Counter(requested_paths).most_common(5),
            }
        )

    return detections


def summarize_web_logs(events):
    total_404 = sum(1 for event in events if event["status"] == NOT_FOUND_STATUS)
    status_counts = Counter(event["status"] for event in events)
    ip_counts = Counter(event["ip"] for event in events)

    return {
        "total_events": len(events),
        "total_404": total_404,
        "status_counts": status_counts,
        "ip_counts": ip_counts,
    }


def get_404_detection_severity(detections):
    if not detections:
        return "info"

    highest_count = max(detection["count"] for detection in detections)

    if highest_count >= 8:
        return "high"

    if highest_count >= 5:
        return "medium"

    return "low"


def build_404_evidence(detections):
    evidence = []

    for detection in detections:
        paths = ", ".join(detection["paths"][:5])
        evidence.append(
            f"ip={detection['ip']} repeated_404_count={detection['count']} "
            f"first_seen={detection['first_seen']} last_seen={detection['last_seen']} paths={paths}"
        )

    return evidence


def save_repeated_404_finding(detections):
    if not detections:
        return None

    finding = create_finding(
        title="Repeated 404 pattern detected",
        description="Repeated 404 responses were detected in local sample web logs, which may indicate content discovery or scanning behavior.",
        severity=get_404_detection_severity(detections),
        category="soc_lab",
        source_module="repeated_404_detector",
        mitre_technique="T1595",
        evidence=build_404_evidence(detections),
        recommendations=[
            "Review source IP addresses with repeated 404 responses.",
            "Check whether requested paths match sensitive files or admin panels.",
            "Create alerts for repeated 404 spikes from the same source.",
            "Rate-limit suspicious sources when appropriate.",
            "Harden exposed web applications and remove sensitive files from web roots.",
        ],
    )

    append_finding(finding)
    return finding


def print_web_summary(summary):
    print("Web log summary:")
    print(f"- Total events: {summary['total_events']}")
    print(f"- Total 404 responses: {summary['total_404']}")
    print()

    print("Status code counts:")
    for status, count in summary["status_counts"].most_common():
        print(f"- {status}: {count}")

    print()
    print("Top source IPs:")
    for ip_address, count in summary["ip_counts"].most_common():
        print(f"- {ip_address}: {count}")


def print_404_detections(detections):
    if not detections:
        print("No repeated 404 pattern was detected.")
        return

    print("Repeated 404 patterns detected:")
    print()

    for index, detection in enumerate(detections, start=1):
        print(f"Detection {index}:")
        print(f"- IP: {detection['ip']}")
        print(f"- 404 count: {detection['count']}")
        print(f"- First seen: {detection['first_seen']}")
        print(f"- Last seen: {detection['last_seen']}")
        print("- Requested paths:")

        for path in detection["paths"][:10]:
            print(f"  - {path}")

        print()


def run_repeated_404_detector():
    print_section_title("Detect Repeated 404 Pattern")
    print("This module detects repeated 404 responses in local sample web logs.")
    print("It does not scan or connect to any web application.")
    print(f"Log source: {DEFAULT_WEB_LOG_PATH}")
    print(f"Repeated 404 threshold: {REPEATED_404_THRESHOLD}")
    print()

    events = load_web_logs()

    if not events:
        print("No web log events were found.")
        print("Check the sample web log file path and content.")
        return

    summary = summarize_web_logs(events)
    detections = detect_repeated_404_patterns(events)

    print_web_summary(summary)
    print()
    print_404_detections(detections)

    if detections:
        print(f"Severity estimate: {get_404_detection_severity(detections)}")
        print()

    answer = input("Save repeated 404 detection as a local finding? (y/n): ").strip().lower()

    if answer == "y":
        finding = save_repeated_404_finding(detections)

        if finding:
            print("Repeated 404 detection finding saved to local findings store.")
        else:
            print("No finding was saved because no detection was found.")
    else:
        print("Repeated 404 detection finding was not saved.")