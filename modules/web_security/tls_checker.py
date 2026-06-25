from pathlib import Path
from urllib.parse import urlparse

from app.banner import print_section_title
from core.finding import create_finding
from core.report_store import append_finding


DEFAULT_TLS_SAMPLE_PATH = Path("samples/tls_https_sample.txt")

MODERN_TLS_VERSIONS = {
    "TLS1.2",
    "TLS1.3",
}

DEPRECATED_TLS_VERSIONS = {
    "SSL2.0",
    "SSL3.0",
    "TLS1.0",
    "TLS1.1",
}


def parse_bool(value):
    return str(value).strip().lower() in {"true", "yes", "1", "enabled"}


def parse_int(value, default=0):
    try:
        return int(str(value).strip())
    except ValueError:
        return default


def parse_key_value_sample(raw_text):
    values = {}

    for line in raw_text.splitlines():
        cleaned_line = line.strip()

        if not cleaned_line:
            continue

        if cleaned_line.startswith("#"):
            continue

        if "=" not in cleaned_line:
            continue

        key, value = cleaned_line.split("=", 1)
        values[key.strip().lower()] = value.strip()

    return values


def load_tls_sample(path=DEFAULT_TLS_SAMPLE_PATH):
    target = Path(path)

    if not target.exists():
        return {}

    return parse_key_value_sample(target.read_text(encoding="utf-8"))


def normalize_tls_version(version):
    return str(version).strip().upper().replace(" ", "")


def is_https_url(url):
    parsed = urlparse(url)
    return parsed.scheme.lower() == "https"


def get_tls_version_status(tls_version):
    normalized = normalize_tls_version(tls_version)

    if normalized in DEPRECATED_TLS_VERSIONS:
        return "deprecated"

    if normalized in MODERN_TLS_VERSIONS:
        return "modern"

    if not normalized:
        return "unknown"

    return "review"


def analyze_tls_observation(observation):
    url = observation.get("url", "")
    tls_version = observation.get("tls_version", "")
    cert_days = parse_int(observation.get("certificate_days_remaining", "0"))
    hsts_enabled = parse_bool(observation.get("hsts_enabled", "false"))
    redirects_http = parse_bool(observation.get("redirects_http_to_https", "false"))
    mixed_content = parse_bool(observation.get("mixed_content_detected", "false"))
    cert_trusted = parse_bool(observation.get("certificate_trusted", "false"))

    issues = []

    if not is_https_url(url):
        issues.append(
            {
                "name": "URL does not use HTTPS",
                "severity": "high",
                "why": "HTTP does not protect confidentiality or integrity in transit.",
                "recommendation": "Use HTTPS for all sensitive pages and redirect HTTP traffic to HTTPS.",
            }
        )

    tls_status = get_tls_version_status(tls_version)

    if tls_status == "deprecated":
        issues.append(
            {
                "name": "Deprecated TLS version",
                "severity": "high",
                "why": "Old TLS or SSL versions are not suitable for modern secure transport.",
                "recommendation": "Disable SSL and deprecated TLS versions; prefer TLS 1.2 or TLS 1.3.",
            }
        )

    if tls_status == "unknown":
        issues.append(
            {
                "name": "Unknown TLS version",
                "severity": "medium",
                "why": "TLS version could not be determined from the provided sample.",
                "recommendation": "Verify the server TLS configuration with an authorized TLS assessment tool.",
            }
        )

    if cert_days <= 0:
        issues.append(
            {
                "name": "Certificate expired or invalid",
                "severity": "high",
                "why": "Expired certificates can break trust and expose users to security warnings.",
                "recommendation": "Renew the certificate and confirm the full certificate chain is valid.",
            }
        )
    elif cert_days <= 30:
        issues.append(
            {
                "name": "Certificate expires soon",
                "severity": "medium",
                "why": "Certificates close to expiration may cause service disruption.",
                "recommendation": "Renew the certificate before expiration and monitor certificate lifetime.",
            }
        )

    if not cert_trusted:
        issues.append(
            {
                "name": "Certificate is not trusted",
                "severity": "high",
                "why": "Untrusted certificates can cause browser warnings and weaken user trust.",
                "recommendation": "Use a trusted certificate authority and verify the certificate chain.",
            }
        )

    if not hsts_enabled and is_https_url(url):
        issues.append(
            {
                "name": "HSTS is not enabled",
                "severity": "medium",
                "why": "HSTS helps enforce HTTPS for future browser requests.",
                "recommendation": "Enable Strict-Transport-Security with an appropriate max-age value.",
            }
        )

    if not redirects_http:
        issues.append(
            {
                "name": "HTTP to HTTPS redirect is missing",
                "severity": "medium",
                "why": "Users may accidentally access the HTTP version of a site.",
                "recommendation": "Redirect HTTP requests to HTTPS for the same host and path.",
            }
        )

    if mixed_content:
        issues.append(
            {
                "name": "Mixed content detected",
                "severity": "medium",
                "why": "Loading insecure HTTP resources inside HTTPS pages weakens page security.",
                "recommendation": "Load scripts, stylesheets, images, and other resources over HTTPS.",
            }
        )

    return {
        "url": url,
        "tls_version": tls_version or "unknown",
        "tls_status": tls_status,
        "certificate_days_remaining": cert_days,
        "hsts_enabled": hsts_enabled,
        "redirects_http_to_https": redirects_http,
        "mixed_content_detected": mixed_content,
        "certificate_trusted": cert_trusted,
        "issues": issues,
    }


def get_tls_analysis_severity(result):
    severities = [issue["severity"] for issue in result["issues"]]

    if "high" in severities:
        return "high"

    if "medium" in severities:
        return "medium"

    if "low" in severities:
        return "low"

    return "info"


def build_tls_evidence(result):
    evidence = [
        f"url={result['url']}",
        f"tls_version={result['tls_version']}",
        f"tls_status={result['tls_status']}",
        f"certificate_days_remaining={result['certificate_days_remaining']}",
        f"hsts_enabled={result['hsts_enabled']}",
        f"redirects_http_to_https={result['redirects_http_to_https']}",
        f"mixed_content_detected={result['mixed_content_detected']}",
        f"certificate_trusted={result['certificate_trusted']}",
        f"issue_count={len(result['issues'])}",
    ]

    for issue in result["issues"]:
        evidence.append(f"issue={issue['name']} severity={issue['severity']}")

    return evidence


def build_tls_recommendations(result):
    recommendations = [issue["recommendation"] for issue in result["issues"]]

    if not recommendations:
        recommendations.append("Continue monitoring HTTPS and TLS configuration after deployment changes.")

    return list(dict.fromkeys(recommendations))


def save_tls_analysis_finding(result):
    if not result["issues"]:
        return None

    finding = create_finding(
        title="TLS and HTTPS configuration issues detected",
        description="One or more HTTPS or TLS configuration issues were detected in the analyzed local sample.",
        severity=get_tls_analysis_severity(result),
        category="web_security",
        source_module="tls_checker",
        mitre_technique="N/A",
        evidence=build_tls_evidence(result),
        recommendations=build_tls_recommendations(result),
    )

    append_finding(finding)
    return finding


def print_tls_result(result):
    print("TLS / HTTPS analysis result:")
    print(f"- URL: {result['url']}")
    print(f"- TLS version: {result['tls_version']}")
    print(f"- TLS status: {result['tls_status']}")
    print(f"- Certificate days remaining: {result['certificate_days_remaining']}")
    print(f"- HSTS enabled: {result['hsts_enabled']}")
    print(f"- Redirects HTTP to HTTPS: {result['redirects_http_to_https']}")
    print(f"- Mixed content detected: {result['mixed_content_detected']}")
    print(f"- Certificate trusted: {result['certificate_trusted']}")
    print()

    if result["issues"]:
        print("Issues:")

        for issue in result["issues"]:
            print(f"- {issue['name']} [{issue['severity']}]")
            print(f"  Why: {issue['why']}")
            print(f"  Recommendation: {issue['recommendation']}")
    else:
        print("Issues: None")

    print()


def read_manual_observation():
    print("Enter TLS / HTTPS observation values.")
    print("Leave empty to use default safe values where possible.")
    print()

    url = input("URL: ").strip() or "https://example.local"
    tls_version = input("TLS version (TLS1.2 / TLS1.3 / TLS1.0 etc.): ").strip() or "TLS1.2"
    cert_days = input("Certificate days remaining: ").strip() or "90"
    hsts_enabled = input("HSTS enabled? (true/false): ").strip() or "true"
    redirects_http = input("Redirects HTTP to HTTPS? (true/false): ").strip() or "true"
    mixed_content = input("Mixed content detected? (true/false): ").strip() or "false"
    cert_trusted = input("Certificate trusted? (true/false): ").strip() or "true"

    return {
        "url": url,
        "tls_version": tls_version,
        "certificate_days_remaining": cert_days,
        "hsts_enabled": hsts_enabled,
        "redirects_http_to_https": redirects_http,
        "mixed_content_detected": mixed_content,
        "certificate_trusted": cert_trusted,
    }


def run_tls_checker():
    print_section_title("TLS / HTTPS Basic Check")
    print("This module analyzes local or manually provided TLS / HTTPS observations.")
    print("It does not connect to remote hosts, scan ports, or test live certificates.")
    print()
    print("[1] Analyze sample TLS / HTTPS observation file")
    print("[2] Enter TLS / HTTPS observations manually")
    print("[0] Back")
    print()

    choice = input("Select an option: ").strip()

    if choice == "0":
        return

    if choice == "1":
        observation = load_tls_sample()
        source = str(DEFAULT_TLS_SAMPLE_PATH)
    elif choice == "2":
        observation = read_manual_observation()
        source = "manual_input"
    else:
        print("Invalid option.")
        return

    if not observation:
        print("No valid TLS / HTTPS observation values were found.")
        return

    result = analyze_tls_observation(observation)

    print()
    print(f"Analysis source: {source}")
    print()
    print_tls_result(result)
    print(f"Severity estimate: {get_tls_analysis_severity(result)}")
    print()

    answer = input("Save TLS / HTTPS analysis as a local finding? (y/n): ").strip().lower()

    if answer == "y":
        finding = save_tls_analysis_finding(result)

        if finding:
            print("TLS / HTTPS analysis finding saved to local findings store.")
        else:
            print("No finding was saved because no TLS / HTTPS issue was detected.")
    else:
        print("TLS / HTTPS analysis finding was not saved.")