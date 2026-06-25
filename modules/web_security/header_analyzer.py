from pathlib import Path

from app.banner import print_section_title
from core.finding import create_finding
from core.report_store import append_finding


DEFAULT_HEADERS_PATH = Path("samples/http_headers.txt")

SECURITY_HEADERS = {
    "content-security-policy": {
        "display_name": "Content-Security-Policy",
        "severity": "high",
        "why": "Helps reduce the impact of XSS and content injection attacks.",
        "recommendation": "Define a strict Content-Security-Policy that only allows trusted sources.",
    },
    "strict-transport-security": {
        "display_name": "Strict-Transport-Security",
        "severity": "medium",
        "why": "Forces browsers to use HTTPS for future requests.",
        "recommendation": "Enable HSTS on HTTPS sites with an appropriate max-age value.",
    },
    "x-frame-options": {
        "display_name": "X-Frame-Options",
        "severity": "medium",
        "why": "Helps protect against clickjacking.",
        "recommendation": "Use DENY or SAMEORIGIN unless framing is intentionally required.",
    },
    "x-content-type-options": {
        "display_name": "X-Content-Type-Options",
        "severity": "low",
        "why": "Prevents MIME type sniffing in supported browsers.",
        "recommendation": "Set X-Content-Type-Options to nosniff.",
    },
    "referrer-policy": {
        "display_name": "Referrer-Policy",
        "severity": "low",
        "why": "Controls how much referrer information is sent with requests.",
        "recommendation": "Use a privacy-conscious policy such as no-referrer or strict-origin-when-cross-origin.",
    },
    "permissions-policy": {
        "display_name": "Permissions-Policy",
        "severity": "low",
        "why": "Limits browser features such as camera, microphone, geolocation, and payment APIs.",
        "recommendation": "Disable unused browser features with a restrictive Permissions-Policy.",
    },
}


def normalize_header_name(name):
    return name.strip().lower()


def parse_headers_from_text(raw_text):
    headers = {}

    for line in raw_text.splitlines():
        cleaned_line = line.strip()

        if not cleaned_line:
            continue

        if cleaned_line.startswith("#"):
            continue

        if cleaned_line.upper().startswith("HTTP/"):
            continue

        if ":" not in cleaned_line:
            continue

        name, value = cleaned_line.split(":", 1)
        headers[normalize_header_name(name)] = value.strip()

    return headers


def load_headers_from_file(path=DEFAULT_HEADERS_PATH):
    target = Path(path)

    if not target.exists():
        return {}

    raw_text = target.read_text(encoding="utf-8")
    return parse_headers_from_text(raw_text)


def analyze_security_headers(headers):
    results = []

    for header_name, metadata in SECURITY_HEADERS.items():
        value = headers.get(header_name)

        if value:
            status = "present"
            message = f"{metadata['display_name']} is present."
        else:
            status = "missing"
            message = f"{metadata['display_name']} is missing."

        results.append(
            {
                "header": metadata["display_name"],
                "status": status,
                "value": value or "N/A",
                "severity": metadata["severity"],
                "why": metadata["why"],
                "message": message,
                "recommendation": metadata["recommendation"],
            }
        )

    return results


def get_missing_headers(results):
    return [result for result in results if result["status"] == "missing"]


def get_header_analysis_severity(results):
    missing_headers = get_missing_headers(results)
    missing_names = {item["header"] for item in missing_headers}

    if "Content-Security-Policy" in missing_names:
        return "high"

    if "Strict-Transport-Security" in missing_names or "X-Frame-Options" in missing_names:
        return "medium"

    if missing_headers:
        return "low"

    return "info"


def build_header_finding_evidence(results):
    evidence = []

    for result in results:
        evidence.append(
            f"{result['header']}: status={result['status']} value={result['value']}"
        )

    return evidence


def build_header_recommendations(results):
    recommendations = []

    for result in get_missing_headers(results):
        recommendations.append(result["recommendation"])

    if not recommendations:
        recommendations.append("Continue monitoring HTTP security headers after application changes.")

    return recommendations


def save_header_analysis_finding(results):
    missing_headers = get_missing_headers(results)

    if not missing_headers:
        return None

    finding = create_finding(
        title="Missing HTTP security headers detected",
        description="One or more recommended HTTP security headers were missing from the analyzed local header sample.",
        severity=get_header_analysis_severity(results),
        category="web_security",
        source_module="header_analyzer",
        mitre_technique="N/A",
        evidence=build_header_finding_evidence(results),
        recommendations=build_header_recommendations(results),
    )

    append_finding(finding)
    return finding


def print_header_results(results):
    print("HTTP security header analysis:")
    print()

    for result in results:
        print(f"- {result['header']}")
        print(f"  Status: {result['status']}")
        print(f"  Value: {result['value']}")
        print(f"  Why it matters: {result['why']}")

        if result["status"] == "missing":
            print(f"  Recommendation: {result['recommendation']}")

        print()


def run_header_analyzer():
    print_section_title("HTTP Security Header Analyzer")
    print("This module analyzes local or pasted HTTP response headers.")
    print("It does not scan websites, exploit targets, or connect to external systems.")
    print()
    print("[1] Analyze sample header file")
    print("[2] Paste headers manually")
    print("[0] Back")
    print()

    choice = input("Select an option: ").strip()

    if choice == "0":
        return

    if choice == "1":
        headers = load_headers_from_file()
        source = str(DEFAULT_HEADERS_PATH)
    elif choice == "2":
        print()
        print("Paste HTTP headers. Enter an empty line to finish.")
        lines = []

        while True:
            line = input()

            if not line.strip():
                break

            lines.append(line)

        headers = parse_headers_from_text("\n".join(lines))
        source = "manual_input"
    else:
        print("Invalid option.")
        return

    if not headers:
        print("No valid HTTP headers were found.")
        return

    print()
    print(f"Analysis source: {source}")
    print(f"Parsed headers: {len(headers)}")
    print()

    results = analyze_security_headers(headers)
    print_header_results(results)

    missing_headers = get_missing_headers(results)
    print(f"Missing recommended headers: {len(missing_headers)}")
    print(f"Severity estimate: {get_header_analysis_severity(results)}")
    print()

    answer = input("Save header analysis as a local finding? (y/n): ").strip().lower()

    if answer == "y":
        finding = save_header_analysis_finding(results)

        if finding:
            print("HTTP header analysis finding saved to local findings store.")
        else:
            print("No finding was saved because no missing security header was detected.")
    else:
        print("HTTP header analysis finding was not saved.")