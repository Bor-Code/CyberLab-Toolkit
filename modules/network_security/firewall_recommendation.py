from pathlib import Path

from app.banner import print_section_title
from core.finding import create_finding
from core.report_store import append_finding


DEFAULT_FIREWALL_SAMPLE_PATH = Path("samples/firewall_rules.txt")

SENSITIVE_INBOUND_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    445: "SMB",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    27017: "MongoDB",
    9200: "Elasticsearch",
}

PUBLIC_WEB_PORTS = {
    80: "HTTP",
    443: "HTTPS",
}

PUBLIC_SOURCES = {
    "0.0.0.0/0",
    "::/0",
    "any",
    "*",
}


def load_firewall_rules_from_file(path=DEFAULT_FIREWALL_SAMPLE_PATH):
    target = Path(path)

    if not target.exists():
        return []

    rules = []

    for line in target.read_text(encoding="utf-8").splitlines():
        cleaned_line = line.strip()

        if not cleaned_line:
            continue

        if cleaned_line.startswith("#"):
            continue

        parts = [part.strip() for part in cleaned_line.split(",")]

        if len(parts) < 6:
            continue

        try:
            port = int(parts[3])
        except ValueError:
            continue

        rules.append(
            {
                "action": parts[0].lower(),
                "direction": parts[1].lower(),
                "protocol": parts[2].lower(),
                "port": port,
                "source": parts[4].lower(),
                "note": parts[5],
            }
        )

    return rules


def is_public_source(source):
    return source.lower() in PUBLIC_SOURCES


def classify_firewall_rule(rule):
    action = rule["action"]
    direction = rule["direction"]
    port = rule["port"]
    source = rule["source"]

    if action == "deny":
        return {
            **rule,
            "classification": "explicit-deny",
            "risk": "info",
            "recommendation": "Explicit deny rules help document blocked exposure.",
        }

    if direction != "inbound":
        return {
            **rule,
            "classification": "outbound-rule",
            "risk": "info",
            "recommendation": "Review outbound rules for business need and monitoring coverage.",
        }

    if action == "allow" and port in SENSITIVE_INBOUND_PORTS and is_public_source(source):
        return {
            **rule,
            "classification": "sensitive-service-publicly-allowed",
            "risk": "high",
            "recommendation": f"Do not expose {SENSITIVE_INBOUND_PORTS[port]} to all networks. Restrict it with VPN, allowlist, or internal-only access.",
        }

    if action == "allow" and port in SENSITIVE_INBOUND_PORTS:
        return {
            **rule,
            "classification": "sensitive-service-restricted",
            "risk": "medium",
            "recommendation": f"Confirm {SENSITIVE_INBOUND_PORTS[port]} access is limited to trusted sources.",
        }

    if action == "allow" and port in PUBLIC_WEB_PORTS and is_public_source(source):
        return {
            **rule,
            "classification": "public-web-service",
            "risk": "low",
            "recommendation": f"Ensure {PUBLIC_WEB_PORTS[port]} is patched, monitored, and intentionally public.",
        }

    if action == "allow" and is_public_source(source):
        return {
            **rule,
            "classification": "publicly-allowed-service",
            "risk": "medium",
            "recommendation": "Review whether this publicly allowed service is required.",
        }

    return {
        **rule,
        "classification": "restricted-rule",
        "risk": "low",
        "recommendation": "Confirm the rule is documented and still required.",
    }


def analyze_firewall_rules(rules):
    return [classify_firewall_rule(rule) for rule in rules]


def summarize_firewall_results(results):
    summary = {
        "total": len(results),
        "allow": 0,
        "deny": 0,
        "inbound": 0,
        "outbound": 0,
        "high_risk": 0,
        "medium_risk": 0,
        "low_risk": 0,
        "info_risk": 0,
    }

    for result in results:
        if result["action"] == "allow":
            summary["allow"] += 1
        elif result["action"] == "deny":
            summary["deny"] += 1

        if result["direction"] == "inbound":
            summary["inbound"] += 1
        elif result["direction"] == "outbound":
            summary["outbound"] += 1

        if result["risk"] == "high":
            summary["high_risk"] += 1
        elif result["risk"] == "medium":
            summary["medium_risk"] += 1
        elif result["risk"] == "low":
            summary["low_risk"] += 1
        else:
            summary["info_risk"] += 1

    return summary


def get_firewall_severity(summary):
    if summary["high_risk"] >= 2:
        return "high"

    if summary["high_risk"] == 1:
        return "medium"

    if summary["medium_risk"] >= 1:
        return "medium"

    if summary["low_risk"] >= 1:
        return "low"

    return "info"


def build_firewall_evidence(results, summary):
    evidence = [
        f"Total firewall rule observations: {summary['total']}",
        f"Allow rules: {summary['allow']}",
        f"Deny rules: {summary['deny']}",
        f"Inbound rules: {summary['inbound']}",
        f"Outbound rules: {summary['outbound']}",
        f"High risk rules: {summary['high_risk']}",
        f"Medium risk rules: {summary['medium_risk']}",
        f"Low risk rules: {summary['low_risk']}",
    ]

    for result in results:
        evidence.append(
            f"action={result['action']} direction={result['direction']} "
            f"protocol={result['protocol']} port={result['port']} source={result['source']} "
            f"classification={result['classification']} risk={result['risk']}"
        )

    return evidence


def build_firewall_recommendations(results):
    recommendations = [
        "Use default-deny logic for inbound traffic where possible.",
        "Expose only services that are required and documented.",
        "Restrict administrative and database services to trusted networks.",
        "Review public allow rules regularly.",
    ]

    for result in results:
        if result["risk"] in {"high", "medium"}:
            recommendations.append(result["recommendation"])

    return list(dict.fromkeys(recommendations))


def save_firewall_finding(results, summary):
    if summary["total"] == 0:
        return None

    finding = create_finding(
        title="Firewall recommendation review completed",
        description="Local firewall rule observations were reviewed for basic defensive hardening recommendations.",
        severity=get_firewall_severity(summary),
        category="network_security",
        source_module="firewall_recommendation",
        mitre_technique="N/A",
        evidence=build_firewall_evidence(results, summary),
        recommendations=build_firewall_recommendations(results),
    )

    append_finding(finding)
    return finding


def print_firewall_result(result):
    print(f"- Rule: {result['action']} {result['direction']} {result['protocol']} {result['port']}")
    print(f"  Source: {result['source']}")
    print(f"  Note: {result['note']}")
    print(f"  Classification: {result['classification']}")
    print(f"  Risk: {result['risk']}")
    print(f"  Recommendation: {result['recommendation']}")


def print_firewall_summary(summary):
    print("Firewall rule summary:")
    print(f"- Total: {summary['total']}")
    print(f"- Allow: {summary['allow']}")
    print(f"- Deny: {summary['deny']}")
    print(f"- Inbound: {summary['inbound']}")
    print(f"- Outbound: {summary['outbound']}")
    print(f"- High risk: {summary['high_risk']}")
    print(f"- Medium risk: {summary['medium_risk']}")
    print(f"- Low risk: {summary['low_risk']}")
    print(f"- Info risk: {summary['info_risk']}")


def run_firewall_recommendation():
    print_section_title("Simple Firewall Recommendation")
    print("This module reviews local firewall rule samples and gives defensive recommendations.")
    print("It does not change firewall settings, scan networks, or connect to targets.")
    print()

    rules = load_firewall_rules_from_file()

    if not rules:
        print("No firewall rule observations were found.")
        return

    results = analyze_firewall_rules(rules)
    summary = summarize_firewall_results(results)

    for result in results:
        print_firewall_result(result)
        print()

    print_firewall_summary(summary)
    print()
    print(f"Severity estimate: {get_firewall_severity(summary)}")
    print()

    answer = input("Save firewall recommendation review as a local finding? (y/n): ").strip().lower()

    if answer == "y":
        save_firewall_finding(results, summary)
        print("Firewall recommendation finding saved to local findings store.")
    else:
        print("Firewall recommendation finding was not saved.")