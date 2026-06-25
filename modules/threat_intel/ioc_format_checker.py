from pathlib import Path
from urllib.parse import urlparse
import ipaddress
import re

from app.banner import print_section_title
from core.finding import create_finding
from core.report_store import append_finding


DEFAULT_IOC_SAMPLE_PATH = Path("samples/iocs.txt")

HASH_PATTERNS = {
    "MD5": re.compile(r"^[a-fA-F0-9]{32}$"),
    "SHA1": re.compile(r"^[a-fA-F0-9]{40}$"),
    "SHA256": re.compile(r"^[a-fA-F0-9]{64}$"),
}

DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?!-)([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$"
)


def load_iocs_from_file(path=DEFAULT_IOC_SAMPLE_PATH):
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


def detect_ip_type(value):
    try:
        ip_object = ipaddress.ip_address(value)

        if ip_object.version == 4:
            return "IPv4"

        if ip_object.version == 6:
            return "IPv6"

    except ValueError:
        return None

    return None


def detect_hash_type(value):
    for hash_type, pattern in HASH_PATTERNS.items():
        if pattern.match(value):
            return hash_type

    return None


def is_valid_domain(value):
    if DOMAIN_PATTERN.match(value):
        return True

    return False


def is_valid_url(value):
    parsed = urlparse(value)

    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def detect_ioc_format(value):
    cleaned_value = value.strip()

    if not cleaned_value:
        return {
            "value": value,
            "type": "unknown",
            "valid": False,
            "details": "Empty value",
        }

    ip_type = detect_ip_type(cleaned_value)

    if ip_type:
        return {
            "value": cleaned_value,
            "type": ip_type,
            "valid": True,
            "details": "Valid IP address format",
        }

    hash_type = detect_hash_type(cleaned_value)

    if hash_type:
        return {
            "value": cleaned_value,
            "type": hash_type,
            "valid": True,
            "details": f"Valid {hash_type} hash format",
        }

    if is_valid_url(cleaned_value):
        parsed = urlparse(cleaned_value)

        return {
            "value": cleaned_value,
            "type": "URL",
            "valid": True,
            "details": f"Valid URL format using {parsed.scheme.upper()}",
        }

    if is_valid_domain(cleaned_value):
        return {
            "value": cleaned_value,
            "type": "Domain",
            "valid": True,
            "details": "Valid domain format",
        }

    return {
        "value": cleaned_value,
        "type": "unknown",
        "valid": False,
        "details": "Could not identify a supported IOC format",
    }


def analyze_ioc_formats(indicators):
    return [detect_ioc_format(indicator) for indicator in indicators]


def summarize_ioc_formats(results):
    summary = {
        "total": len(results),
        "valid": 0,
        "unknown": 0,
        "types": {},
    }

    for result in results:
        if result["valid"]:
            summary["valid"] += 1
        else:
            summary["unknown"] += 1

        indicator_type = result["type"]
        summary["types"][indicator_type] = summary["types"].get(indicator_type, 0) + 1

    return summary


def get_ioc_format_severity(summary):
    if summary["total"] == 0:
        return "info"

    if summary["unknown"] >= 5:
        return "medium"

    if summary["unknown"] >= 1:
        return "low"

    return "info"


def build_ioc_format_evidence(results, summary):
    evidence = [
        f"Total indicators analyzed: {summary['total']}",
        f"Valid indicators: {summary['valid']}",
        f"Unknown or unsupported indicators: {summary['unknown']}",
    ]

    for indicator_type, count in summary["types"].items():
        evidence.append(f"Detected type count: {indicator_type}={count}")

    for result in results:
        evidence.append(
            f"value={result['value']} type={result['type']} valid={result['valid']} details={result['details']}"
        )

    return evidence


def build_ioc_format_recommendations(summary):
    recommendations = [
        "Validate IOC format before enrichment, blocking, alerting, or reporting.",
        "Separate IP addresses, domains, URLs, and hashes before deeper analysis.",
        "Manually review unknown indicators before using them in detections.",
    ]

    if summary["unknown"]:
        recommendations.append("Clean unsupported or malformed indicator values before sharing the IOC list.")

    return recommendations


def save_ioc_format_finding(results, summary):
    if summary["total"] == 0:
        return None

    finding = create_finding(
        title="IOC format analysis completed",
        description="Local indicators were analyzed and classified by basic IOC format.",
        severity=get_ioc_format_severity(summary),
        category="threat_intel",
        source_module="ioc_format_checker",
        mitre_technique="N/A",
        evidence=build_ioc_format_evidence(results, summary),
        recommendations=build_ioc_format_recommendations(summary),
    )

    append_finding(finding)
    return finding


def print_ioc_result(result):
    print(f"- Indicator: {result['value']}")
    print(f"  Type: {result['type']}")
    print(f"  Valid: {result['valid']}")
    print(f"  Details: {result['details']}")


def print_ioc_summary(summary):
    print("IOC format summary:")
    print(f"- Total indicators: {summary['total']}")
    print(f"- Valid indicators: {summary['valid']}")
    print(f"- Unknown indicators: {summary['unknown']}")
    print()

    print("Type counts:")

    for indicator_type, count in summary["types"].items():
        print(f"- {indicator_type}: {count}")


def read_manual_iocs():
    print("Paste indicators. Enter an empty line to finish.")
    indicators = []

    while True:
        line = input().strip()

        if not line:
            break

        indicators.append(line)

    return indicators


def run_ioc_format_checker():
    print_section_title("IOC Format Checker")
    print("This module identifies basic IOC formats from local or pasted indicators.")
    print("It does not query threat intelligence APIs, download files, or contact external systems.")
    print()
    print("[1] Analyze sample IOC file")
    print("[2] Paste indicators manually")
    print("[0] Back")
    print()

    choice = input("Select an option: ").strip()

    if choice == "0":
        return

    if choice == "1":
        indicators = load_iocs_from_file()
        source = str(DEFAULT_IOC_SAMPLE_PATH)
    elif choice == "2":
        indicators = read_manual_iocs()
        source = "manual_input"
    else:
        print("Invalid option.")
        return

    if not indicators:
        print("No indicators were found.")
        return

    results = analyze_ioc_formats(indicators)
    summary = summarize_ioc_formats(results)

    print()
    print(f"Analysis source: {source}")
    print()

    for result in results:
        print_ioc_result(result)
        print()

    print_ioc_summary(summary)
    print()
    print(f"Severity estimate: {get_ioc_format_severity(summary)}")
    print()

    answer = input("Save IOC format analysis as a local finding? (y/n): ").strip().lower()

    if answer == "y":
        finding = save_ioc_format_finding(results, summary)

        if finding:
            print("IOC format analysis finding saved to local findings store.")
        else:
            print("No finding was saved because no indicators were analyzed.")
    else:
        print("IOC format analysis finding was not saved.")