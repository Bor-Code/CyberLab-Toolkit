from app.banner import print_section_title
from core.finding import create_finding
from core.report_store import append_finding
from modules.web_security.cookie_checker import analyze_cookies, load_cookies_from_file
from modules.web_security.header_analyzer import analyze_security_headers, load_headers_from_file
from modules.web_security.tls_checker import analyze_tls_observation, load_tls_sample
from modules.web_security.url_checker import analyze_urls, load_urls_from_file


SEVERITY_POINTS = {
    "info": 0,
    "low": 5,
    "medium": 15,
    "high": 30,
    "critical": 45,
}


def severity_to_points(severity):
    return SEVERITY_POINTS.get(severity, 0)


def get_issue_severity(issue):
    return issue.get("severity", "info")


def calculate_header_score(header_results):
    score = 0

    for result in header_results:
        if result["status"] == "missing":
            score += severity_to_points(result["severity"])

    return score


def calculate_cookie_score(cookie_results):
    score = 0

    for result in cookie_results:
        for issue in result["issues"]:
            score += severity_to_points(get_issue_severity(issue))

    return score


def calculate_tls_score(tls_result):
    score = 0

    for issue in tls_result["issues"]:
        score += severity_to_points(get_issue_severity(issue))

    return score


def calculate_url_score(url_results):
    score = 0

    for result in url_results:
        for issue in result["issues"]:
            score += severity_to_points(get_issue_severity(issue))

    return score


def clamp_score(score):
    if score < 0:
        return 0

    if score > 100:
        return 100

    return score


def score_to_severity(score):
    if score >= 85:
        return "critical"

    if score >= 65:
        return "high"

    if score >= 35:
        return "medium"

    if score >= 10:
        return "low"

    return "info"


def score_to_label(score):
    if score >= 85:
        return "Critical Web Risk"

    if score >= 65:
        return "High Web Risk"

    if score >= 35:
        return "Medium Web Risk"

    if score >= 10:
        return "Low Web Risk"

    return "Informational Web Risk"


def build_web_risk_summary():
    header_results = analyze_security_headers(load_headers_from_file())
    cookie_results = analyze_cookies(load_cookies_from_file())
    tls_result = analyze_tls_observation(load_tls_sample())
    url_results = analyze_urls(load_urls_from_file())

    header_score = calculate_header_score(header_results)
    cookie_score = calculate_cookie_score(cookie_results)
    tls_score = calculate_tls_score(tls_result)
    url_score = calculate_url_score(url_results)

    total_raw_score = header_score + cookie_score + tls_score + url_score
    final_score = clamp_score(total_raw_score)

    header_issues = sum(1 for result in header_results if result["status"] == "missing")
    cookie_issues = sum(len(result["issues"]) for result in cookie_results)
    tls_issues = len(tls_result["issues"])
    url_issues = sum(len(result["issues"]) for result in url_results)

    return {
        "score": final_score,
        "raw_score": total_raw_score,
        "severity": score_to_severity(final_score),
        "label": score_to_label(final_score),
        "header_score": header_score,
        "cookie_score": cookie_score,
        "tls_score": tls_score,
        "url_score": url_score,
        "header_issues": header_issues,
        "cookie_issues": cookie_issues,
        "tls_issues": tls_issues,
        "url_issues": url_issues,
        "header_results": header_results,
        "cookie_results": cookie_results,
        "tls_result": tls_result,
        "url_results": url_results,
    }


def build_web_risk_evidence(summary):
    evidence = [
        f"Final web risk score: {summary['score']}/100",
        f"Raw score before clamp: {summary['raw_score']}",
        f"Severity: {summary['severity']}",
        f"Header score contribution: {summary['header_score']}",
        f"Cookie score contribution: {summary['cookie_score']}",
        f"TLS / HTTPS score contribution: {summary['tls_score']}",
        f"URL structure score contribution: {summary['url_score']}",
        f"Missing security headers: {summary['header_issues']}",
        f"Cookie security issues: {summary['cookie_issues']}",
        f"TLS / HTTPS issues: {summary['tls_issues']}",
        f"Suspicious URL structure issues: {summary['url_issues']}",
    ]

    for result in summary["header_results"]:
        if result["status"] == "missing":
            evidence.append(f"Missing header: {result['header']} severity={result['severity']}")

    for result in summary["cookie_results"]:
        if result["issues"]:
            evidence.append(f"Cookie issue count: cookie={result['cookie']['name']} issues={len(result['issues'])}")

    for issue in summary["tls_result"]["issues"]:
        evidence.append(f"TLS issue: {issue['name']} severity={issue['severity']}")

    for result in summary["url_results"]:
        if result["issues"]:
            evidence.append(
                f"URL issue count: hostname={result['hostname']} issues={len(result['issues'])}"
            )

    return evidence


def build_web_risk_recommendations(summary):
    recommendations = [
        "Review all web security findings together rather than as isolated issues.",
        "Prioritize high-severity missing headers, HTTPS problems, and risky cookie configurations.",
        "Re-test the sample observations after remediation to confirm the risk score decreases.",
    ]

    if summary["header_issues"]:
        recommendations.append("Add missing HTTP security headers such as CSP, HSTS, and Permissions-Policy where appropriate.")

    if summary["cookie_issues"]:
        recommendations.append("Set Secure, HttpOnly, and SameSite attributes on sensitive cookies.")

    if summary["tls_issues"]:
        recommendations.append("Review HTTPS, certificate lifetime, HSTS, redirects, and mixed content indicators.")

    if summary["url_issues"]:
        recommendations.append("Review suspicious URLs for unsafe redirects, risky file extensions, IP-based hostnames, and encoded content.")

    return list(dict.fromkeys(recommendations))


def save_web_risk_finding(summary):
    if summary["score"] == 0:
        return None

    finding = create_finding(
        title="Web security risk score calculated",
        description="Local web security observations were analyzed and converted into a combined web risk score.",
        severity=summary["severity"],
        category="web_security",
        source_module="web_risk_score",
        mitre_technique="N/A",
        evidence=build_web_risk_evidence(summary),
        recommendations=build_web_risk_recommendations(summary),
    )

    append_finding(finding)
    return finding


def print_score_bar(score):
    filled_units = score // 10
    empty_units = 10 - filled_units
    bar = "#" * filled_units + "-" * empty_units

    print(f"Risk score: [{bar}] {score}/100")


def print_web_risk_summary(summary):
    print("Combined Web Security Risk Summary:")
    print()
    print_score_bar(summary["score"])
    print(f"Risk label: {summary['label']}")
    print(f"Severity: {summary['severity']}")
    print(f"Raw score before clamp: {summary['raw_score']}")
    print()
    print("Score contribution:")
    print(f"- HTTP security headers: {summary['header_score']}")
    print(f"- Cookie security: {summary['cookie_score']}")
    print(f"- TLS / HTTPS: {summary['tls_score']}")
    print(f"- URL structure: {summary['url_score']}")
    print()
    print("Issue count:")
    print(f"- Missing security headers: {summary['header_issues']}")
    print(f"- Cookie security issues: {summary['cookie_issues']}")
    print(f"- TLS / HTTPS issues: {summary['tls_issues']}")
    print(f"- Suspicious URL structure issues: {summary['url_issues']}")


def run_web_risk_score():
    print_section_title("Web Risk Score Calculator")
    print("This module calculates a combined web security risk score from local sample observations.")
    print("It does not scan websites, exploit systems, or connect to external targets.")
    print()

    summary = build_web_risk_summary()
    print_web_risk_summary(summary)
    print()

    answer = input("Save web risk score as a local finding? (y/n): ").strip().lower()

    if answer == "y":
        finding = save_web_risk_finding(summary)

        if finding:
            print("Web risk score finding saved to local findings store.")
        else:
            print("No finding was saved because the risk score is informational.")
    else:
        print("Web risk score finding was not saved.")