from pathlib import Path
import ipaddress

from app.banner import print_section_title
from core.finding import create_finding
from core.report_store import append_finding


DEFAULT_IP_SAMPLE_PATH = Path("samples/ip_indicators.txt")


def load_ip_indicators_from_file(path=DEFAULT_IP_SAMPLE_PATH):
    target = Path(path)

    if not target.exists():
        return []

    indicators = []

    for line in target.read_text(encoding="utf-8").splitlines():
        cleaned_line = line.strip()

        if not cleaned_line:
            continue

        if cleaned_line.startswith("#"):
            continue

        indicators.append(cleaned_line)

    return indicators


def parse_ip(value):
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def classify_ip_object(ip_object):
    if ip_object.is_loopback:
        return "loopback"

    if ip_object.is_private:
        return "private"

    if ip_object.is_link_local:
        return "link-local"

    if ip_object.is_multicast:
        return "multicast"

    if ip_object.is_reserved:
        return "reserved"

    if ip_object.is_unspecified:
        return "unspecified"

    if ip_object.is_global:
        return "public"

    return "other"


def get_ip_risk_level(classification):
    if classification == "public":
        return "medium"

    if classification in {"private", "loopback", "link-local"}:
        return "low"

    if classification in {"multicast", "reserved", "unspecified"}:
        return "low"

    return "info"


def get_ip_recommendation(classification):
    if classification == "public":
        return "Review public IP indicators before blocking, alerting, or enriching them."

    if classification == "private":
        return "Private IP indicators usually belong to internal networks and need local context."

    if classification == "loopback":
        return "Loopback indicators usually point to the local host and should not be treated as internet IOCs."

    if classification == "link-local":
        return "Link-local addresses usually require local network context before investigation."

    if classification == "multicast":
        return "Multicast addresses are normally not external threat indicators."

    if classification == "reserved":
        return "Reserved addresses should be reviewed before using them in detections."

    if classification == "unspecified":
        return "Unspecified addresses are not useful as external threat indicators."

    return "Review the indicator manually before using it in detections."


def analyze_ip_indicator(value):
    ip_object = parse_ip(value)

    if not ip_object:
        return {
            "value": value,
            "valid": False,
            "version": "unknown",
            "classification": "invalid",
            "risk": "info",
            "is_global": False,
            "is_private": False,
            "is_loopback": False,
            "recommendation": "Remove or correct invalid IP indicator values before reporting.",
        }

    classification = classify_ip_object(ip_object)

    return {
        "value": value,
        "valid": True,
        "version": f"IPv{ip_object.version}",
        "classification": classification,
        "risk": get_ip_risk_level(classification),
        "is_global": ip_object.is_global,
        "is_private": ip_object.is_private,
        "is_loopback": ip_object.is_loopback,
        "recommendation": get_ip_recommendation(classification),
    }


def analyze_ip_indicators(indicators):
    return [analyze_ip_indicator(indicator) for indicator in indicators]


def summarize_ip_results(results):
    summary = {
        "total": len(results),
        "valid": 0,
        "invalid": 0,
        "public": 0,
        "private": 0,
        "loopback": 0,
        "link-local": 0,
        "multicast": 0,
        "reserved": 0,
        "unspecified": 0,
        "other": 0,
    }

    for result in results:
        if result["valid"]:
            summary["valid"] += 1
        else:
            summary["invalid"] += 1

        classification = result["classification"]

        if classification in summary:
            summary[classification] += 1
        else:
            summary["other"] += 1

    return summary


def get_ip_analysis_severity(summary):
    if summary["invalid"] >= 3:
        return "medium"

    if summary["public"] >= 1:
        return "low"

    if summary["invalid"] >= 1:
        return "low"

    return "info"


def build_ip_evidence(results, summary):
    evidence = [
        f"Total IP indicators analyzed: {summary['total']}",
        f"Valid IP indicators: {summary['valid']}",
        f"Invalid IP indicators: {summary['invalid']}",
        f"Public IP indicators: {summary['public']}",
        f"Private IP indicators: {summary['private']}",
        f"Loopback IP indicators: {summary['loopback']}",
    ]

    for result in results:
        evidence.append(
            f"value={result['value']} valid={result['valid']} "
            f"version={result['version']} classification={result['classification']} risk={result['risk']}"
        )

    return evidence


def build_ip_recommendations(results, summary):
    recommendations = [
        "Separate public IP indicators from private, loopback, reserved, and invalid values.",
        "Do not treat private or loopback addresses as internet threat indicators without local context.",
        "Validate IP indicators before sharing, blocking, alerting, or enrichment.",
    ]

    if summary["invalid"]:
        recommendations.append("Correct or remove invalid IP values from the IOC list.")

    if summary["public"]:
        recommendations.append("Review public IP indicators with additional context before operational use.")

    return list(dict.fromkeys(recommendations))


def save_ip_classification_finding(results, summary):
    if summary["total"] == 0:
        return None

    finding = create_finding(
        title="IP indicator classification completed",
        description="Local IP indicators were classified by address type and basic investigation context.",
        severity=get_ip_analysis_severity(summary),
        category="threat_intel",
        source_module="ip_classifier",
        mitre_technique="N/A",
        evidence=build_ip_evidence(results, summary),
        recommendations=build_ip_recommendations(results, summary),
    )

    append_finding(finding)
    return finding


def print_ip_result(result):
    print(f"- Indicator: {result['value']}")
    print(f"  Valid: {result['valid']}")
    print(f"  Version: {result['version']}")
    print(f"  Classification: {result['classification']}")
    print(f"  Risk: {result['risk']}")
    print(f"  Recommendation: {result['recommendation']}")


def print_ip_summary(summary):
    print("IP indicator summary:")
    print(f"- Total: {summary['total']}")
    print(f"- Valid: {summary['valid']}")
    print(f"- Invalid: {summary['invalid']}")
    print(f"- Public: {summary['public']}")
    print(f"- Private: {summary['private']}")
    print(f"- Loopback: {summary['loopback']}")
    print(f"- Link-local: {summary['link-local']}")
    print(f"- Multicast: {summary['multicast']}")
    print(f"- Reserved: {summary['reserved']}")
    print(f"- Unspecified: {summary['unspecified']}")
    print(f"- Other: {summary['other']}")


def read_manual_ip_indicators():
    print("Paste IP indicators. Enter an empty line to finish.")
    indicators = []

    while True:
        line = input().strip()

        if not line:
            break

        indicators.append(line)

    return indicators


def run_ip_classifier():
    print_section_title("IP Indicator Classifier")
    print("This module classifies local or pasted IP indicators.")
    print("It does not query external APIs, scan hosts, or connect to IP addresses.")
    print()
    print("[1] Analyze sample IP indicator file")
    print("[2] Paste IP indicators manually")
    print("[0] Back")
    print()

    choice = input("Select an option: ").strip()

    if choice == "0":
        return

    if choice == "1":
        indicators = load_ip_indicators_from_file()
        source = str(DEFAULT_IP_SAMPLE_PATH)
    elif choice == "2":
        indicators = read_manual_ip_indicators()
        source = "manual_input"
    else:
        print("Invalid option.")
        return

    if not indicators:
        print("No IP indicators were found.")
        return

    results = analyze_ip_indicators(indicators)
    summary = summarize_ip_results(results)

    print()
    print(f"Analysis source: {source}")
    print()

    for result in results:
        print_ip_result(result)
        print()

    print_ip_summary(summary)
    print()
    print(f"Severity estimate: {get_ip_analysis_severity(summary)}")
    print()

    answer = input("Save IP classification as a local finding? (y/n): ").strip().lower()

    if answer == "y":
        finding = save_ip_classification_finding(results, summary)

        if finding:
            print("IP classification finding saved to local findings store.")
        else:
            print("No finding was saved because no IP indicators were analyzed.")
    else:
        print("IP classification finding was not saved.")