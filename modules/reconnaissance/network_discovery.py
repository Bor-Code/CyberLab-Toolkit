from pathlib import Path

from app.banner import print_section_title
from core.finding import create_finding
from core.report_store import append_finding


DEFAULT_NETWORK_SAMPLE_PATH = Path("samples/local_network_devices.txt")

KNOWN_DEVICE_TYPES = {
    "router",
    "workstation",
    "mobile",
    "iot",
    "printer",
    "virtual-machine",
}

SENSITIVE_DEVICE_TYPES = {
    "router",
    "iot",
    "unknown",
}

OFFLINE_STATUS = {
    "offline",
    "unknown",
}


def load_network_devices(path=DEFAULT_NETWORK_SAMPLE_PATH):
    target = Path(path)

    if not target.exists():
        return []

    devices = []

    for line in target.read_text(encoding="utf-8").splitlines():
        cleaned_line = line.strip()

        if not cleaned_line:
            continue

        if cleaned_line.startswith("#"):
            continue

        parts = [part.strip() for part in cleaned_line.split(",")]

        if len(parts) < 6:
            continue

        devices.append(
            {
                "ip": parts[0],
                "hostname": parts[1],
                "mac_vendor": parts[2],
                "device_type": parts[3].lower(),
                "status": parts[4].lower(),
                "notes": parts[5],
            }
        )

    return devices


def classify_device(device):
    device_type = device["device_type"]
    status = device["status"]
    vendor = device["mac_vendor"].lower()
    hostname = device["hostname"].lower()
    notes = []
    score = 0

    if device_type not in KNOWN_DEVICE_TYPES:
        notes.append("Unknown or uncommon device type.")
        score += 2

    if device_type in SENSITIVE_DEVICE_TYPES:
        notes.append("Device type should be reviewed carefully in a local network inventory.")
        score += 2

    if status in OFFLINE_STATUS:
        notes.append("Device is not currently marked as online.")
        score += 1

    if vendor == "unknown":
        notes.append("MAC vendor is unknown.")
        score += 2

    if "unknown" in hostname:
        notes.append("Hostname contains unknown marker.")
        score += 2

    if device_type == "router":
        notes.append("Router or gateway device should be documented clearly.")
        score += 1

    if not notes:
        notes.append("Device looks normal in the local sample inventory.")

    if score >= 5:
        risk = "medium"
        classification = "needs-review"
    elif score >= 2:
        risk = "low"
        classification = "review"
    else:
        risk = "info"
        classification = "documented"

    return {
        "ip": device["ip"],
        "hostname": device["hostname"],
        "mac_vendor": device["mac_vendor"],
        "device_type": device["device_type"],
        "status": device["status"],
        "notes": notes,
        "score": score,
        "risk": risk,
        "classification": classification,
        "recommendation": get_device_recommendation(classification),
    }


def get_device_recommendation(classification):
    if classification == "needs-review":
        return "Review this device in the authorized local network inventory and verify ownership."

    if classification == "review":
        return "Keep this device documented and confirm that its role is understood."

    return "No immediate action required beyond normal documentation."


def analyze_network_devices(devices):
    return [classify_device(device) for device in devices]


def summarize_network_devices(results):
    summary = {
        "total": len(results),
        "online": 0,
        "offline": 0,
        "unknown_type": 0,
        "needs_review": 0,
        "low_risk": 0,
        "info_risk": 0,
    }

    for result in results:
        if result["status"] == "online":
            summary["online"] += 1
        else:
            summary["offline"] += 1

        if result["device_type"] not in KNOWN_DEVICE_TYPES:
            summary["unknown_type"] += 1

        if result["risk"] == "medium":
            summary["needs_review"] += 1
        elif result["risk"] == "low":
            summary["low_risk"] += 1
        else:
            summary["info_risk"] += 1

    return summary


def get_network_discovery_severity(summary):
    if summary["needs_review"] >= 2:
        return "medium"

    if summary["needs_review"] == 1:
        return "low"

    if summary["unknown_type"] >= 1:
        return "low"

    return "info"


def build_network_evidence(results, summary):
    evidence = [
        f"Total devices reviewed: {summary['total']}",
        f"Online devices: {summary['online']}",
        f"Offline devices: {summary['offline']}",
        f"Unknown device types: {summary['unknown_type']}",
        f"Devices needing review: {summary['needs_review']}",
    ]

    for result in results:
        evidence.append(
            f"ip={result['ip']} hostname={result['hostname']} type={result['device_type']} "
            f"status={result['status']} risk={result['risk']} score={result['score']}"
        )

    return evidence


def build_network_recommendations(results):
    recommendations = [
        "Maintain an authorized inventory of known local network devices.",
        "Review unknown hostnames, unknown vendors, and uncommon device types.",
        "Document routers, IoT devices, printers, and lab virtual machines clearly.",
        "Do not scan networks without explicit permission.",
    ]

    for result in results:
        if result["risk"] in {"medium", "low"}:
            recommendations.append(result["recommendation"])

    return list(dict.fromkeys(recommendations))


def save_network_discovery_finding(results, summary):
    if summary["total"] == 0:
        return None

    finding = create_finding(
        title="Local network inventory review completed",
        description="Safe local sample network devices were reviewed for inventory and documentation practice.",
        severity=get_network_discovery_severity(summary),
        category="reconnaissance",
        source_module="network_discovery",
        mitre_technique="N/A",
        evidence=build_network_evidence(results, summary),
        recommendations=build_network_recommendations(results),
    )

    append_finding(finding)
    return finding


def print_device_result(result):
    print(f"- IP: {result['ip']}")
    print(f"  Hostname: {result['hostname']}")
    print(f"  Vendor: {result['mac_vendor']}")
    print(f"  Type: {result['device_type']}")
    print(f"  Status: {result['status']}")
    print(f"  Classification: {result['classification']}")
    print(f"  Risk: {result['risk']}")
    print(f"  Score: {result['score']}")
    print("  Notes:")

    for note in result["notes"]:
        print(f"  - {note}")

    print(f"  Recommendation: {result['recommendation']}")


def print_network_summary(summary):
    print("Local network inventory summary:")
    print(f"- Total devices: {summary['total']}")
    print(f"- Online devices: {summary['online']}")
    print(f"- Offline devices: {summary['offline']}")
    print(f"- Unknown device types: {summary['unknown_type']}")
    print(f"- Devices needing review: {summary['needs_review']}")
    print(f"- Low risk devices: {summary['low_risk']}")
    print(f"- Info risk devices: {summary['info_risk']}")


def run_network_discovery():
    print_section_title("Local Network Device Discovery")
    print("This module reviews a safe local sample network inventory.")
    print("It does not scan real networks, send packets, or connect to devices.")
    print()

    devices = load_network_devices()

    if not devices:
        print("No local network sample devices were found.")
        return

    results = analyze_network_devices(devices)
    summary = summarize_network_devices(results)

    for result in results:
        print_device_result(result)
        print()

    print_network_summary(summary)
    print()
    print(f"Severity estimate: {get_network_discovery_severity(summary)}")
    print()

    answer = input("Save local network inventory review as a local finding? (y/n): ").strip().lower()

    if answer == "y":
        save_network_discovery_finding(results, summary)
        print("Local network inventory finding saved to local findings store.")
    else:
        print("Local network inventory finding was not saved.")