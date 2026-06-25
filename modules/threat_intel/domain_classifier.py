from pathlib import Path
import ipaddress
import re

from app.banner import print_section_title
from core.finding import create_finding
from core.report_store import append_finding


DEFAULT_DOMAIN_SAMPLE_PATH = Path("samples/domain_indicators.txt")

DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?!-)([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$"
)

SUSPICIOUS_DOMAIN_KEYWORDS = [
    "login",
    "secure",
    "verify",
    "account",
    "update",
    "download",
    "malware",
    "payment",
    "wallet",
    "bank",
]

INTERNAL_SUFFIXES = [
    ".local",
    ".lan",
    ".internal",
    ".corp",
]


def load_domain_indicators_from_file(path=DEFAULT_DOMAIN_SAMPLE_PATH):
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


def is_ip_address(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_valid_domain(value):
    return DOMAIN_PATTERN.match(value) is not None


def is_internal_domain(value):
    lowered_value = value.lower()

    if lowered_value == "localhost":
        return True

    return any(lowered_value.endswith(suffix) for suffix in INTERNAL_SUFFIXES)


def is_punycode_domain(value):
    lowered_value = value.lower()

    return lowered_value.startswith("xn--") or ".xn--" in lowered_value


def get_subdomain_count(value):
    parts = [part for part in value.split(".") if part]

    if len(parts) <= 2:
        return 0

    return len(parts) - 2


def find_domain_keywords(value):
    lowered_value = value.lower()

    return [keyword for keyword in SUSPICIOUS_DOMAIN_KEYWORDS if keyword in lowered_value]


def classify_domain(value):
    cleaned_value = value.strip().lower()

    if not cleaned_value:
        return {
            "value": value,
            "valid": False,
            "classification": "invalid",
            "risk": "info",
            "subdomain_count": 0,
            "keywords": [],
            "notes": ["Empty domain value"],
            "recommendation": "Remove empty domain values from the IOC list.",
        }

    if is_ip_address(cleaned_value):
        return {
            "value": value,
            "valid": False,
            "classification": "ip-address",
            "risk": "low",
            "subdomain_count": 0,
            "keywords": [],
            "notes": ["This value is an IP address, not a domain."],
            "recommendation": "Move IP indicators to the IP classifier workflow.",
        }

    if is_internal_domain(cleaned_value):
        return {
            "value": value,
            "valid": True,
            "classification": "internal-or-local",
            "risk": "low",
            "subdomain_count": get_subdomain_count(cleaned_value),
            "keywords": find_domain_keywords(cleaned_value),
            "notes": ["Internal or local-style domain indicator detected."],
            "recommendation": "Review internal or local domains with local environment context.",
        }

    if not is_valid_domain(cleaned_value):
        return {
            "value": value,
            "valid": False,
            "classification": "invalid",
            "risk": "info",
            "subdomain_count": 0,
            "keywords": find_domain_keywords(cleaned_value),
            "notes": ["Domain format is not valid."],
            "recommendation": "Correct malformed domain values before using them in reports or detections.",
        }

    notes = []
    risk = "info"
    classification = "public-domain"
    subdomain_count = get_subdomain_count(cleaned_value)
    keywords = find_domain_keywords(cleaned_value)

    if is_punycode_domain(cleaned_value):
        notes.append("Punycode domain detected.")
        risk = "medium"
        classification = "punycode-domain"

    if subdomain_count >= 3:
        notes.append("High subdomain depth detected.")

        if risk == "info":
            risk = "low"

    if len(keywords) >= 2:
        notes.append("Multiple sensitive or suspicious keywords detected.")

        if risk in {"info", "low"}:
            risk = "medium"

    if cleaned_value.endswith(".test"):
        notes.append("Reserved testing-style TLD detected.")

        if risk == "info":
            risk = "low"

    if not notes:
        notes.append("No suspicious domain structure indicators detected.")

    return {
        "value": value,
        "valid": True,
        "classification": classification,
        "risk": risk,
        "subdomain_count": subdomain_count,
        "keywords": keywords,
        "notes": notes,
        "recommendation": get_domain_recommendation(classification, risk),
    }


def get_domain_recommendation(classification, risk):
    if classification == "punycode-domain":
        return "Manually verify punycode domains before trusting or sharing them."

    if risk == "medium":
        return "Review this domain with additional context before using it operationally."

    if risk == "low":
        return "Keep this domain in the investigation set but validate its context."

    return "Continue normal domain indicator review."


def analyze_domain_indicators(indicators):
    return [classify_domain(indicator) for indicator in indicators]


def summarize_domain_results(results):
    summary = {
        "total": len(results),
        "valid": 0,
        "invalid": 0,
        "public-domain": 0,
        "internal-or-local": 0,
        "punycode-domain": 0,
        "ip-address": 0,
        "medium_risk": 0,
        "low_risk": 0,
        "info_risk": 0,
    }

    for result in results:
        if result["valid"]:
            summary["valid"] += 1
        else:
            summary["invalid"] += 1

        classification = result["classification"]

        if classification in summary:
            summary[classification] += 1

        if result["risk"] == "medium":
            summary["medium_risk"] += 1
        elif result["risk"] == "low":
            summary["low_risk"] += 1
        else:
            summary["info_risk"] += 1

    return summary


def get_domain_analysis_severity(summary):
    if summary["medium_risk"] >= 2:
        return "medium"

    if summary["medium_risk"] == 1:
        return "low"

    if summary["invalid"] >= 1:
        return "low"

    return "info"


def build_domain_evidence(results, summary):
    evidence = [
        f"Total domain indicators analyzed: {summary['total']}",
        f"Valid domain indicators: {summary['valid']}",
        f"Invalid or non-domain values: {summary['invalid']}",
        f"Public domains: {summary['public-domain']}",
        f"Internal or local domains: {summary['internal-or-local']}",
        f"Punycode domains: {summary['punycode-domain']}",
    ]

    for result in results:
        evidence.append(
            f"value={result['value']} valid={result['valid']} "
            f"classification={result['classification']} risk={result['risk']} "
            f"subdomains={result['subdomain_count']} keywords={','.join(result['keywords']) or 'none'}"
        )

    return evidence


def build_domain_recommendations(summary):
    recommendations = [
        "Validate domain indicators before enrichment, blocking, alerting, or reporting.",
        "Separate public domains from internal, local, invalid, and IP-based values.",
        "Review punycode and keyword-heavy domains manually before trusting them.",
    ]

    if summary["invalid"]:
        recommendations.append("Correct or remove invalid domain values from the IOC list.")

    if summary["internal-or-local"]:
        recommendations.append("Handle internal or local domains using environment-specific context.")

    return list(dict.fromkeys(recommendations))


def save_domain_classification_finding(results, summary):
    if summary["total"] == 0:
        return None

    finding = create_finding(
        title="Domain indicator classification completed",
        description="Local domain indicators were classified by structure and basic investigation context.",
        severity=get_domain_analysis_severity(summary),
        category="threat_intel",
        source_module="domain_classifier",
        mitre_technique="N/A",
        evidence=build_domain_evidence(results, summary),
        recommendations=build_domain_recommendations(summary),
    )

    append_finding(finding)
    return finding


def print_domain_result(result):
    print(f"- Indicator: {result['value']}")
    print(f"  Valid: {result['valid']}")
    print(f"  Classification: {result['classification']}")
    print(f"  Risk: {result['risk']}")
    print(f"  Subdomain count: {result['subdomain_count']}")

    if result["keywords"]:
        print(f"  Keywords: {', '.join(result['keywords'])}")
    else:
        print("  Keywords: None")

    print("  Notes:")

    for note in result["notes"]:
        print(f"  - {note}")

    print(f"  Recommendation: {result['recommendation']}")


def print_domain_summary(summary):
    print("Domain indicator summary:")
    print(f"- Total: {summary['total']}")
    print(f"- Valid: {summary['valid']}")
    print(f"- Invalid / non-domain: {summary['invalid']}")
    print(f"- Public domains: {summary['public-domain']}")
    print(f"- Internal or local: {summary['internal-or-local']}")
    print(f"- Punycode: {summary['punycode-domain']}")
    print(f"- IP-address values: {summary['ip-address']}")
    print(f"- Medium risk: {summary['medium_risk']}")
    print(f"- Low risk: {summary['low_risk']}")
    print(f"- Info risk: {summary['info_risk']}")


def read_manual_domain_indicators():
    print("Paste domain indicators. Enter an empty line to finish.")
    indicators = []

    while True:
        line = input().strip()

        if not line:
            break

        indicators.append(line)

    return indicators


def run_domain_classifier():
    print_section_title("Domain Indicator Classifier")
    print("This module classifies local or pasted domain indicators.")
    print("It does not query DNS, visit domains, or contact external systems.")
    print()
    print("[1] Analyze sample domain indicator file")
    print("[2] Paste domain indicators manually")
    print("[0] Back")
    print()

    choice = input("Select an option: ").strip()

    if choice == "0":
        return

    if choice == "1":
        indicators = load_domain_indicators_from_file()
        source = str(DEFAULT_DOMAIN_SAMPLE_PATH)
    elif choice == "2":
        indicators = read_manual_domain_indicators()
        source = "manual_input"
    else:
        print("Invalid option.")
        return

    if not indicators:
        print("No domain indicators were found.")
        return

    results = analyze_domain_indicators(indicators)
    summary = summarize_domain_results(results)

    print()
    print(f"Analysis source: {source}")
    print()

    for result in results:
        print_domain_result(result)
        print()

    print_domain_summary(summary)
    print()
    print(f"Severity estimate: {get_domain_analysis_severity(summary)}")
    print()

    answer = input("Save domain classification as a local finding? (y/n): ").strip().lower()

    if answer == "y":
        finding = save_domain_classification_finding(results, summary)

        if finding:
            print("Domain classification finding saved to local findings store.")
        else:
            print("No finding was saved because no domain indicators were analyzed.")
    else:
        print("Domain classification finding was not saved.")