from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse
import ipaddress

from app.banner import print_section_title
from core.finding import create_finding
from core.report_store import append_finding


DEFAULT_URL_SAMPLE_PATH = Path("samples/suspicious_urls.txt")

SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "account",
    "secure",
    "update",
    "password",
    "reset",
    "bank",
    "wallet",
    "payment",
]

RISKY_EXTENSIONS = [
    ".exe",
    ".scr",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".jar",
    ".zip",
    ".rar",
]

SHORTENER_DOMAINS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
]


def load_urls_from_file(path=DEFAULT_URL_SAMPLE_PATH):
    target = Path(path)

    if not target.exists():
        return []

    urls = []

    for line in target.read_text(encoding="utf-8").splitlines():
        cleaned_line = line.strip()

        if not cleaned_line:
            continue

        if cleaned_line.startswith("#"):
            continue

        urls.append(cleaned_line)

    return urls


def is_ip_address(hostname):
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def count_subdomains(hostname):
    parts = [part for part in hostname.split(".") if part]

    if len(parts) <= 2:
        return 0

    return len(parts) - 2


def has_risky_extension(path):
    lowered_path = path.lower()

    return any(lowered_path.endswith(extension) for extension in RISKY_EXTENSIONS)


def find_keywords(value):
    lowered_value = value.lower()

    return [keyword for keyword in SUSPICIOUS_KEYWORDS if keyword in lowered_value]


def analyze_url(url):
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    decoded_url = unquote(url)
    decoded_path = unquote(path)
    query_values = parse_qs(query)

    issues = []

    if parsed.scheme.lower() != "https":
        issues.append(
            {
                "name": "URL does not use HTTPS",
                "severity": "high",
                "why": "Non-HTTPS URLs do not protect data in transit.",
                "recommendation": "Use HTTPS for login, account, payment, and sensitive pages.",
            }
        )

    if "@" in url:
        issues.append(
            {
                "name": "URL contains @ symbol",
                "severity": "medium",
                "why": "The @ symbol can make a URL visually misleading.",
                "recommendation": "Review URLs containing @ before trusting or sharing them.",
            }
        )

    if hostname and is_ip_address(hostname):
        issues.append(
            {
                "name": "Hostname is an IP address",
                "severity": "medium",
                "why": "Sensitive web flows normally use trusted domain names, not raw IP addresses.",
                "recommendation": "Use a valid domain name and investigate unexpected IP-based URLs.",
            }
        )

    if hostname.startswith("xn--") or ".xn--" in hostname:
        issues.append(
            {
                "name": "Punycode hostname detected",
                "severity": "medium",
                "why": "Punycode domains can be used for lookalike or homograph-style deception.",
                "recommendation": "Manually verify punycode domains before trusting them.",
            }
        )

    if hostname in SHORTENER_DOMAINS:
        issues.append(
            {
                "name": "URL shortener domain detected",
                "severity": "medium",
                "why": "Shortened URLs hide the final destination.",
                "recommendation": "Expand and verify shortened URLs before use.",
            }
        )

    if count_subdomains(hostname) >= 3:
        issues.append(
            {
                "name": "Excessive subdomain depth",
                "severity": "low",
                "why": "Long subdomain chains can make the real registrable domain harder to notice.",
                "recommendation": "Verify the real domain and avoid relying only on visual similarity.",
            }
        )

    if has_risky_extension(path):
        issues.append(
            {
                "name": "Risky downloadable file extension",
                "severity": "medium",
                "why": "Executable or archive downloads may require additional validation.",
                "recommendation": "Verify the source and scan downloaded files in a safe environment.",
            }
        )

    if "../" in decoded_path or "..\\" in decoded_path:
        issues.append(
            {
                "name": "Path traversal pattern detected",
                "severity": "medium",
                "why": "Path traversal strings in URLs can indicate suspicious probing or unsafe links.",
                "recommendation": "Review paths containing traversal patterns and validate server-side path handling.",
            }
        )

    if len(url) >= 120:
        issues.append(
            {
                "name": "Unusually long URL",
                "severity": "low",
                "why": "Very long URLs can hide suspicious parameters or misleading destinations.",
                "recommendation": "Inspect long URLs carefully before trusting them.",
            }
        )

    if len(query_values) >= 4:
        issues.append(
            {
                "name": "Many query parameters",
                "severity": "low",
                "why": "Many parameters can make URLs harder to review and may expose sensitive values.",
                "recommendation": "Review query strings for tokens, redirects, and unnecessary sensitive data.",
            }
        )

    if "redirect=" in query.lower() or "next=" in query.lower() or "url=" in query.lower():
        issues.append(
            {
                "name": "Redirect-like parameter detected",
                "severity": "medium",
                "why": "Redirect parameters can be abused if not validated by the application.",
                "recommendation": "Allow only trusted redirect destinations and validate redirect parameters server-side.",
            }
        )

    if "%" in url and decoded_url != url:
        issues.append(
            {
                "name": "Encoded characters detected",
                "severity": "low",
                "why": "URL encoding can hide the real structure of a link.",
                "recommendation": "Decode and inspect encoded URLs before trusting them.",
            }
        )

    keywords = find_keywords(url)

    if len(keywords) >= 3:
        issues.append(
            {
                "name": "Multiple sensitive keywords in URL",
                "severity": "low",
                "why": "A URL containing many account or login-related terms may require extra review.",
                "recommendation": "Verify the source and domain before using account-related URLs.",
            }
        )

    return {
        "url": url,
        "scheme": parsed.scheme or "unknown",
        "hostname": hostname or "unknown",
        "path": path or "/",
        "query_parameter_count": len(query_values),
        "subdomain_count": count_subdomains(hostname) if hostname else 0,
        "keywords": keywords,
        "issues": issues,
    }


def analyze_urls(urls):
    return [analyze_url(url) for url in urls]


def get_url_result_severity(result):
    severities = [issue["severity"] for issue in result["issues"]]

    if "high" in severities:
        return "high"

    if "medium" in severities:
        return "medium"

    if "low" in severities:
        return "low"

    return "info"


def get_url_analysis_severity(results):
    severities = [get_url_result_severity(result) for result in results]

    if "high" in severities:
        return "high"

    if "medium" in severities:
        return "medium"

    if "low" in severities:
        return "low"

    return "info"


def build_url_evidence(results):
    evidence = []

    for result in results:
        evidence.append(
            f"url={result['url']} hostname={result['hostname']} "
            f"issues={len(result['issues'])} severity={get_url_result_severity(result)}"
        )

        for issue in result["issues"]:
            evidence.append(f"issue={issue['name']} severity={issue['severity']}")

    return evidence


def build_url_recommendations(results):
    recommendations = []

    for result in results:
        for issue in result["issues"]:
            recommendations.append(issue["recommendation"])

    if not recommendations:
        recommendations.append("Continue reviewing URL structure before sharing or trusting links.")

    return list(dict.fromkeys(recommendations))


def save_url_analysis_finding(results):
    issue_count = sum(len(result["issues"]) for result in results)

    if issue_count == 0:
        return None

    finding = create_finding(
        title="Suspicious URL structure indicators detected",
        description="One or more URLs contained structural indicators that require security review.",
        severity=get_url_analysis_severity(results),
        category="web_security",
        source_module="url_checker",
        mitre_technique="N/A",
        evidence=build_url_evidence(results),
        recommendations=build_url_recommendations(results),
    )

    append_finding(finding)
    return finding


def print_url_result(result):
    print(f"- URL: {result['url']}")
    print(f"  Hostname: {result['hostname']}")
    print(f"  Scheme: {result['scheme']}")
    print(f"  Subdomain count: {result['subdomain_count']}")
    print(f"  Query parameter count: {result['query_parameter_count']}")
    print(f"  Severity: {get_url_result_severity(result)}")

    if result["keywords"]:
        print(f"  Sensitive keywords: {', '.join(result['keywords'])}")
    else:
        print("  Sensitive keywords: None")

    if result["issues"]:
        print("  Issues:")

        for issue in result["issues"]:
            print(f"  - {issue['name']} [{issue['severity']}]")
            print(f"    Why: {issue['why']}")
            print(f"    Recommendation: {issue['recommendation']}")
    else:
        print("  Issues: None")

    print()


def read_manual_urls():
    print("Paste URLs. Enter an empty line to finish.")
    urls = []

    while True:
        line = input().strip()

        if not line:
            break

        urls.append(line)

    return urls


def run_url_checker():
    print_section_title("Suspicious URL Structure Analyzer")
    print("This module analyzes local or pasted URLs for suspicious structure indicators.")
    print("It does not visit URLs, download files, scan targets, or exploit systems.")
    print()
    print("[1] Analyze sample URL file")
    print("[2] Paste URLs manually")
    print("[0] Back")
    print()

    choice = input("Select an option: ").strip()

    if choice == "0":
        return

    if choice == "1":
        urls = load_urls_from_file()
        source = str(DEFAULT_URL_SAMPLE_PATH)
    elif choice == "2":
        urls = read_manual_urls()
        source = "manual_input"
    else:
        print("Invalid option.")
        return

    if not urls:
        print("No valid URLs were found.")
        return

    results = analyze_urls(urls)

    print()
    print(f"Analysis source: {source}")
    print(f"Parsed URLs: {len(urls)}")
    print()

    for result in results:
        print_url_result(result)

    total_issues = sum(len(result["issues"]) for result in results)

    print(f"Total URL issues: {total_issues}")
    print(f"Severity estimate: {get_url_analysis_severity(results)}")
    print()

    answer = input("Save URL analysis as a local finding? (y/n): ").strip().lower()

    if answer == "y":
        finding = save_url_analysis_finding(results)

        if finding:
            print("URL structure analysis finding saved to local findings store.")
        else:
            print("No finding was saved because no URL issue was detected.")
    else:
        print("URL structure analysis finding was not saved.")