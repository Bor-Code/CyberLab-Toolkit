from pathlib import Path
import re

from app.banner import print_section_title
from core.finding import create_finding
from core.report_store import append_finding


DEFAULT_HASH_SAMPLE_PATH = Path("samples/hash_indicators.txt")

HASH_PATTERNS = {
    "MD5": re.compile(r"^[a-fA-F0-9]{32}$"),
    "SHA1": re.compile(r"^[a-fA-F0-9]{40}$"),
    "SHA256": re.compile(r"^[a-fA-F0-9]{64}$"),
    "SHA512": re.compile(r"^[a-fA-F0-9]{128}$"),
}

WEAK_HASH_TYPES = {
    "MD5",
    "SHA1",
}


def load_hash_indicators_from_file(path=DEFAULT_HASH_SAMPLE_PATH):
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


def detect_hash_type(value):
    cleaned_value = value.strip()

    for hash_type, pattern in HASH_PATTERNS.items():
        if pattern.match(cleaned_value):
            return hash_type

    return None


def is_hex_like(value):
    return re.match(r"^[a-fA-F0-9]+$", value.strip()) is not None


def classify_hash_indicator(value):
    cleaned_value = value.strip()
    hash_type = detect_hash_type(cleaned_value)

    if hash_type:
        if hash_type in WEAK_HASH_TYPES:
            risk = "low"
            note = f"{hash_type} is valid as an IOC format, but it is weak for cryptographic integrity use."
            recommendation = "Use this hash for IOC matching only; prefer SHA256 for modern malware and file reputation workflows."
        else:
            risk = "info"
            note = f"{hash_type} is a supported hash IOC format."
            recommendation = "Use this hash with local reports, detections, or authorized enrichment workflows."

        return {
            "value": value,
            "valid": True,
            "hash_type": hash_type,
            "length": len(cleaned_value),
            "hex_only": True,
            "risk": risk,
            "note": note,
            "recommendation": recommendation,
        }

    if is_hex_like(cleaned_value):
        note = "Value contains only hexadecimal characters but does not match a supported hash length."
        recommendation = "Check whether the hash was truncated, copied incorrectly, or uses an unsupported algorithm."
    else:
        note = "Value is not a valid hexadecimal hash indicator."
        recommendation = "Remove or correct malformed hash values before reporting or detection use."

    return {
        "value": value,
        "valid": False,
        "hash_type": "unknown",
        "length": len(cleaned_value),
        "hex_only": is_hex_like(cleaned_value),
        "risk": "low",
        "note": note,
        "recommendation": recommendation,
    }


def analyze_hash_indicators(indicators):
    return [classify_hash_indicator(indicator) for indicator in indicators]


def summarize_hash_results(results):
    summary = {
        "total": len(results),
        "valid": 0,
        "invalid": 0,
        "MD5": 0,
        "SHA1": 0,
        "SHA256": 0,
        "SHA512": 0,
        "unknown": 0,
        "weak_hash_format": 0,
        "non_hex": 0,
    }

    for result in results:
        if result["valid"]:
            summary["valid"] += 1
        else:
            summary["invalid"] += 1

        hash_type = result["hash_type"]

        if hash_type in summary:
            summary[hash_type] += 1
        else:
            summary["unknown"] += 1

        if hash_type in WEAK_HASH_TYPES:
            summary["weak_hash_format"] += 1

        if not result["hex_only"]:
            summary["non_hex"] += 1

    return summary


def get_hash_analysis_severity(summary):
    if summary["invalid"] >= 3:
        return "medium"

    if summary["invalid"] >= 1:
        return "low"

    if summary["weak_hash_format"] >= 1:
        return "low"

    return "info"


def build_hash_evidence(results, summary):
    evidence = [
        f"Total hash indicators analyzed: {summary['total']}",
        f"Valid hash indicators: {summary['valid']}",
        f"Invalid hash indicators: {summary['invalid']}",
        f"MD5 count: {summary['MD5']}",
        f"SHA1 count: {summary['SHA1']}",
        f"SHA256 count: {summary['SHA256']}",
        f"SHA512 count: {summary['SHA512']}",
        f"Weak hash format count: {summary['weak_hash_format']}",
        f"Non-hex value count: {summary['non_hex']}",
    ]

    for result in results:
        evidence.append(
            f"value={result['value']} valid={result['valid']} "
            f"type={result['hash_type']} length={result['length']} hex_only={result['hex_only']}"
        )

    return evidence


def build_hash_recommendations(summary):
    recommendations = [
        "Validate hash length and character set before using indicators in detections or reports.",
        "Prefer SHA256 indicators when possible for modern malware and file reputation workflows.",
        "Keep MD5 and SHA1 as matching indicators only, not as strong integrity proof.",
    ]

    if summary["invalid"]:
        recommendations.append("Correct or remove malformed hash values from the IOC list.")

    if summary["non_hex"]:
        recommendations.append("Review non-hex values because they are not supported hash indicators.")

    return list(dict.fromkeys(recommendations))


def save_hash_classification_finding(results, summary):
    if summary["total"] == 0:
        return None

    finding = create_finding(
        title="Hash indicator classification completed",
        description="Local hash indicators were classified by algorithm pattern, length, and character set.",
        severity=get_hash_analysis_severity(summary),
        category="threat_intel",
        source_module="hash_classifier",
        mitre_technique="N/A",
        evidence=build_hash_evidence(results, summary),
        recommendations=build_hash_recommendations(summary),
    )

    append_finding(finding)
    return finding


def print_hash_result(result):
    print(f"- Indicator: {result['value']}")
    print(f"  Valid: {result['valid']}")
    print(f"  Hash type: {result['hash_type']}")
    print(f"  Length: {result['length']}")
    print(f"  Hex only: {result['hex_only']}")
    print(f"  Risk: {result['risk']}")
    print(f"  Note: {result['note']}")
    print(f"  Recommendation: {result['recommendation']}")


def print_hash_summary(summary):
    print("Hash indicator summary:")
    print(f"- Total: {summary['total']}")
    print(f"- Valid: {summary['valid']}")
    print(f"- Invalid: {summary['invalid']}")
    print(f"- MD5: {summary['MD5']}")
    print(f"- SHA1: {summary['SHA1']}")
    print(f"- SHA256: {summary['SHA256']}")
    print(f"- SHA512: {summary['SHA512']}")
    print(f"- Weak hash format: {summary['weak_hash_format']}")
    print(f"- Non-hex values: {summary['non_hex']}")


def read_manual_hash_indicators():
    print("Paste hash indicators. Enter an empty line to finish.")
    indicators = []

    while True:
        line = input().strip()

        if not line:
            break

        indicators.append(line)

    return indicators


def run_hash_classifier():
    print_section_title("Hash Indicator Classifier")
    print("This module classifies local or pasted hash indicators.")
    print("It does not query external reputation APIs, download files, or execute samples.")
    print()
    print("[1] Analyze sample hash indicator file")
    print("[2] Paste hash indicators manually")
    print("[0] Back")
    print()

    choice = input("Select an option: ").strip()

    if choice == "0":
        return

    if choice == "1":
        indicators = load_hash_indicators_from_file()
        source = str(DEFAULT_HASH_SAMPLE_PATH)
    elif choice == "2":
        indicators = read_manual_hash_indicators()
        source = "manual_input"
    else:
        print("Invalid option.")
        return

    if not indicators:
        print("No hash indicators were found.")
        return

    results = analyze_hash_indicators(indicators)
    summary = summarize_hash_results(results)

    print()
    print(f"Analysis source: {source}")
    print()

    for result in results:
        print_hash_result(result)
        print()

    print_hash_summary(summary)
    print()
    print(f"Severity estimate: {get_hash_analysis_severity(summary)}")
    print()

    answer = input("Save hash classification as a local finding? (y/n): ").strip().lower()

    if answer == "y":
        finding = save_hash_classification_finding(results, summary)

        if finding:
            print("Hash classification finding saved to local findings store.")
        else:
            print("No finding was saved because no hash indicators were analyzed.")
    else:
        print("Hash classification finding was not saved.")