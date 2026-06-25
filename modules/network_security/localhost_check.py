from pathlib import Path

from app.banner import print_section_title
from core.finding import create_finding
from core.report_store import append_finding


DEFAULT_LOCALHOST_SAMPLE_PATH = Path("samples/localhost_services.txt")

SENSITIVE_LOCAL_SERVICES = {
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
    9200: "Elasticsearch",
    3389: "RDP",
}

NORMAL_LOCAL_DEV_SERVICES = {
    3000: "Node or React development server",
    5000: "Flask or development API",
    5173: "Vite development server",
    8000: "Python or development HTTP server",
    8080: "Alternate development HTTP server",
}


def load_localhost_services_from_file(path=DEFAULT_LOCALHOST_SAMPLE_PATH):
    target = Path(path)

    if not target.exists():
        return []

    services = []

    for line in target.read_text(encoding="utf-8").splitlines():
        cleaned_line = line.strip()

        if not cleaned_line:
            continue

        if cleaned_line.startswith("#"):
            continue

        parts = [part.strip() for part in cleaned_line.split(",")]

        if len(parts) < 4:
            continue

        try:
            port = int(parts[0])
        except ValueError:
            continue

        services.append(
            {
                "port": port,
                "state": parts[1].lower(),
                "process": parts[2],
                "note": parts[3],
            }
        )

    return services


def classify_localhost_service(service):
    port = service["port"]
    state = service["state"]

    if state != "listening":
        return {
            **service,
            "classification": "not-listening",
            "risk": "info",
            "recommendation": "No active local listener was recorded for this service entry.",
        }

    if port in SENSITIVE_LOCAL_SERVICES:
        return {
            **service,
            "classification": "sensitive-local-service",
            "risk": "medium",
            "recommendation": f"Confirm that {SENSITIVE_LOCAL_SERVICES[port]} is required locally and not exposed externally.",
        }

    if port in NORMAL_LOCAL_DEV_SERVICES:
        return {
            **service,
            "classification": "local-development-service",
            "risk": "low",
            "recommendation": "Use local development services only while needed and stop them after work.",
        }

    return {
        **service,
        "classification": "unknown-local-service",
        "risk": "low",
        "recommendation": "Review whether this local listening service is expected.",
    }


def analyze_localhost_services(services):
    return [classify_localhost_service(service) for service in services]


def summarize_localhost_results(results):
    summary = {
        "total": len(results),
        "listening": 0,
        "not_listening": 0,
        "medium_risk": 0,
        "low_risk": 0,
        "info_risk": 0,
    }

    for result in results:
        if result["state"] == "listening":
            summary["listening"] += 1
        else:
            summary["not_listening"] += 1

        if result["risk"] == "medium":
            summary["medium_risk"] += 1
        elif result["risk"] == "low":
            summary["low_risk"] += 1
        else:
            summary["info_risk"] += 1

    return summary


def get_localhost_severity(summary):
    if summary["medium_risk"] >= 2:
        return "medium"

    if summary["medium_risk"] == 1:
        return "low"

    if summary["low_risk"] >= 1:
        return "low"

    return "info"


def build_localhost_evidence(results, summary):
    evidence = [
        f"Total localhost service observations: {summary['total']}",
        f"Listening services: {summary['listening']}",
        f"Not listening services: {summary['not_listening']}",
        f"Medium risk observations: {summary['medium_risk']}",
        f"Low risk observations: {summary['low_risk']}",
    ]

    for result in results:
        evidence.append(
            f"port={result['port']} state={result['state']} process={result['process']} "
            f"classification={result['classification']} risk={result['risk']}"
        )

    return evidence


def build_localhost_recommendations(results):
    recommendations = [
        "Review local listeners regularly during development.",
        "Stop development services when they are no longer needed.",
        "Confirm that database, cache, and admin services are bound only to localhost when intended.",
    ]

    for result in results:
        if result["risk"] == "medium":
            recommendations.append(result["recommendation"])

    return list(dict.fromkeys(recommendations))


def save_localhost_finding(results, summary):
    if summary["total"] == 0:
        return None

    finding = create_finding(
        title="Localhost service review completed",
        description="Localhost service observations were reviewed for defensive learning and exposure awareness.",
        severity=get_localhost_severity(summary),
        category="network_security",
        source_module="localhost_check",
        mitre_technique="N/A",
        evidence=build_localhost_evidence(results, summary),
        recommendations=build_localhost_recommendations(results),
    )

    append_finding(finding)
    return finding


def print_localhost_result(result):
    print(f"- Port: {result['port']}")
    print(f"  State: {result['state']}")
    print(f"  Process: {result['process']}")
    print(f"  Note: {result['note']}")
    print(f"  Classification: {result['classification']}")
    print(f"  Risk: {result['risk']}")
    print(f"  Recommendation: {result['recommendation']}")


def print_localhost_summary(summary):
    print("Localhost service summary:")
    print(f"- Total: {summary['total']}")
    print(f"- Listening: {summary['listening']}")
    print(f"- Not listening: {summary['not_listening']}")
    print(f"- Medium risk: {summary['medium_risk']}")
    print(f"- Low risk: {summary['low_risk']}")
    print(f"- Info risk: {summary['info_risk']}")


def run_localhost_check():
    print_section_title("Localhost Service Check")
    print("This module reviews local sample observations for localhost services.")
    print("It does not scan ports, connect to services, or inspect the real system.")
    print()

    services = load_localhost_services_from_file()

    if not services:
        print("No localhost service observations were found.")
        return

    results = analyze_localhost_services(services)
    summary = summarize_localhost_results(results)

    for result in results:
        print_localhost_result(result)
        print()

    print_localhost_summary(summary)
    print()
    print(f"Severity estimate: {get_localhost_severity(summary)}")
    print()

    answer = input("Save localhost service review as a local finding? (y/n): ").strip().lower()

    if answer == "y":
        save_localhost_finding(results, summary)
        print("Localhost service finding saved to local findings store.")
    else:
        print("Localhost service finding was not saved.")