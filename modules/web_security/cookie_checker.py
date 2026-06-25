from pathlib import Path

from app.banner import print_section_title
from core.finding import create_finding
from core.report_store import append_finding


DEFAULT_COOKIE_PATH = Path("samples/cookies.txt")

REQUIRED_ATTRIBUTES = {
    "secure": {
        "display_name": "Secure",
        "severity": "medium",
        "why": "Ensures the cookie is only sent over HTTPS connections.",
        "recommendation": "Add the Secure attribute to cookies that contain session or sensitive values.",
    },
    "httponly": {
        "display_name": "HttpOnly",
        "severity": "medium",
        "why": "Reduces the risk of client-side scripts accessing cookie values.",
        "recommendation": "Add the HttpOnly attribute to session and authentication cookies.",
    },
    "samesite": {
        "display_name": "SameSite",
        "severity": "low",
        "why": "Helps reduce cross-site request risks.",
        "recommendation": "Set SameSite=Lax or SameSite=Strict unless cross-site usage is required.",
    },
}


SENSITIVE_COOKIE_HINTS = [
    "session",
    "sid",
    "token",
    "auth",
    "jwt",
    "csrf",
    "remember",
]


def clean_cookie_line(line):
    cleaned_line = line.strip()

    if not cleaned_line:
        return ""

    if cleaned_line.startswith("#"):
        return ""

    if cleaned_line.lower().startswith("set-cookie:"):
        cleaned_line = cleaned_line.split(":", 1)[1].strip()

    return cleaned_line


def parse_cookie_line(line):
    cleaned_line = clean_cookie_line(line)

    if not cleaned_line:
        return None

    parts = [part.strip() for part in cleaned_line.split(";") if part.strip()]

    if not parts or "=" not in parts[0]:
        return None

    cookie_name, cookie_value = parts[0].split("=", 1)

    attributes = {}

    for attribute in parts[1:]:
        if "=" in attribute:
            key, value = attribute.split("=", 1)
            attributes[key.strip().lower()] = value.strip()
        else:
            attributes[attribute.strip().lower()] = True

    return {
        "name": cookie_name.strip(),
        "value": cookie_value.strip(),
        "attributes": attributes,
        "raw": cleaned_line,
    }


def load_cookies_from_file(path=DEFAULT_COOKIE_PATH):
    target = Path(path)

    if not target.exists():
        return []

    cookies = []

    for line in target.read_text(encoding="utf-8").splitlines():
        cookie = parse_cookie_line(line)

        if cookie:
            cookies.append(cookie)

    return cookies


def is_sensitive_cookie(cookie):
    cookie_name = cookie["name"].lower()

    return any(hint in cookie_name for hint in SENSITIVE_COOKIE_HINTS)


def get_cookie_attribute_status(cookie):
    attributes = cookie["attributes"]

    return {
        "Secure": "secure" in attributes,
        "HttpOnly": "httponly" in attributes,
        "SameSite": "samesite" in attributes,
    }


def analyze_cookie(cookie):
    attribute_status = get_cookie_attribute_status(cookie)
    missing = [name for name, present in attribute_status.items() if not present]
    issues = []

    for attribute_name in missing:
        metadata = REQUIRED_ATTRIBUTES[attribute_name.lower()]

        issues.append(
            {
                "attribute": metadata["display_name"],
                "severity": metadata["severity"],
                "why": metadata["why"],
                "recommendation": metadata["recommendation"],
            }
        )

    same_site_value = cookie["attributes"].get("samesite")

    if same_site_value and same_site_value.lower() == "none" and "secure" not in cookie["attributes"]:
        issues.append(
            {
                "attribute": "SameSite=None without Secure",
                "severity": "medium",
                "why": "Modern browsers expect SameSite=None cookies to also use Secure.",
                "recommendation": "Use Secure with SameSite=None or avoid SameSite=None when cross-site cookies are not needed.",
            }
        )

    if is_sensitive_cookie(cookie) and missing:
        sensitivity_note = "Cookie name suggests it may be sensitive."

        for issue in issues:
            issue["why"] = f"{issue['why']} {sensitivity_note}"

    return {
        "cookie": cookie,
        "attribute_status": attribute_status,
        "issues": issues,
    }


def analyze_cookies(cookies):
    return [analyze_cookie(cookie) for cookie in cookies]


def get_cookie_analysis_severity(results):
    severities = []

    for result in results:
        for issue in result["issues"]:
            severities.append(issue["severity"])

    if "high" in severities:
        return "high"

    if "medium" in severities:
        return "medium"

    if "low" in severities:
        return "low"

    return "info"


def build_cookie_evidence(results):
    evidence = []

    for result in results:
        cookie = result["cookie"]
        status = result["attribute_status"]

        evidence.append(
            f"cookie={cookie['name']} Secure={status['Secure']} "
            f"HttpOnly={status['HttpOnly']} SameSite={status['SameSite']} "
            f"issues={len(result['issues'])}"
        )

    return evidence


def build_cookie_recommendations(results):
    recommendations = []

    for result in results:
        for issue in result["issues"]:
            recommendations.append(issue["recommendation"])

    if not recommendations:
        recommendations.append("Continue reviewing cookie security attributes after application changes.")

    return list(dict.fromkeys(recommendations))


def save_cookie_analysis_finding(results):
    issue_count = sum(len(result["issues"]) for result in results)

    if issue_count == 0:
        return None

    finding = create_finding(
        title="Cookie security attribute issues detected",
        description="One or more cookies were missing recommended security attributes in the analyzed local sample.",
        severity=get_cookie_analysis_severity(results),
        category="web_security",
        source_module="cookie_checker",
        mitre_technique="N/A",
        evidence=build_cookie_evidence(results),
        recommendations=build_cookie_recommendations(results),
    )

    append_finding(finding)
    return finding


def print_cookie_result(result):
    cookie = result["cookie"]
    status = result["attribute_status"]

    print(f"- Cookie: {cookie['name']}")
    print(f"  Secure: {status['Secure']}")
    print(f"  HttpOnly: {status['HttpOnly']}")
    print(f"  SameSite: {status['SameSite']}")

    if result["issues"]:
        print("  Issues:")

        for issue in result["issues"]:
            print(f"  - {issue['attribute']}: {issue['why']}")
            print(f"    Recommendation: {issue['recommendation']}")
    else:
        print("  Issues: None")

    print()


def run_cookie_checker():
    print_section_title("Cookie Security Checker")
    print("This module analyzes local or pasted Set-Cookie headers.")
    print("It does not scan websites, steal cookies, or connect to external systems.")
    print()
    print("[1] Analyze sample cookie file")
    print("[2] Paste Set-Cookie headers manually")
    print("[0] Back")
    print()

    choice = input("Select an option: ").strip()

    if choice == "0":
        return

    if choice == "1":
        cookies = load_cookies_from_file()
        source = str(DEFAULT_COOKIE_PATH)
    elif choice == "2":
        print()
        print("Paste Set-Cookie headers. Enter an empty line to finish.")
        lines = []

        while True:
            line = input()

            if not line.strip():
                break

            lines.append(line)

        cookies = []

        for line in lines:
            cookie = parse_cookie_line(line)

            if cookie:
                cookies.append(cookie)

        source = "manual_input"
    else:
        print("Invalid option.")
        return

    if not cookies:
        print("No valid cookies were found.")
        return

    results = analyze_cookies(cookies)

    print()
    print(f"Analysis source: {source}")
    print(f"Parsed cookies: {len(cookies)}")
    print()

    for result in results:
        print_cookie_result(result)

    total_issues = sum(len(result["issues"]) for result in results)

    print(f"Total cookie issues: {total_issues}")
    print(f"Severity estimate: {get_cookie_analysis_severity(results)}")
    print()

    answer = input("Save cookie analysis as a local finding? (y/n): ").strip().lower()

    if answer == "y":
        finding = save_cookie_analysis_finding(results)

        if finding:
            print("Cookie security analysis finding saved to local findings store.")
        else:
            print("No finding was saved because no cookie issue was detected.")
    else:
        print("Cookie security analysis finding was not saved.")