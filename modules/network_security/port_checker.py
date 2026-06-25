from pathlib import Path

from app.banner import print_section_title
from core.finding import create_finding
from core.report_store import append_finding


DEFAULT_PORT_SAMPLE_PATH = Path("samples/port_observations.txt")

HIGH_RISK_PORTS = {
    21: "FTP",
    23: "Telnet",
    445: "SMB",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
}

COMMON_ALLOWED_PORTS = {
    80: "HTTP",
    443: "HTTPS",
}


def load_port_observations_from_file(path=DEFAULT_PORT_SAMPLE_PATH):
    target = Path(path)

    if not target.exists():
        return []

    observations = []

    for line in target.read_text(encoding="utf-8").splitlines():
        cleaned_line = line.strip()

        if not cleaned_line:
            continue

        if cleaned_line.startswith("#"):
            continue

        parts = [part.strip() for part in cleaned_line.split(",")]

        if len(parts) < 5:
            continue

        try:
            port = int(parts[0])
        except ValueError:
            continue

        observations.append(
            {
                "port": port,
                "protocol": parts[1].lower(),
                "state": parts[2].lower(),
                "service": parts[3],
                "note": parts[4],
            }
        )

    return observations


def classify_port_observation(observation):
    port = observation["port"]
    state = observation["state"]

    if state != "open":
        return {
            **observation,
            "risk": "info",
            "classification": "not-open",
            "recommendation": "Closed or filtered ports usually do not require exposure remediation.",
        }

    if port in HIGH_RISK_PORTS:
        return {
            **observation,
            "risk": "medium",
            "classification": "sensitive-service-open",
            "recommendation": f"Restrict access to {HIGH_RISK_PORTS[port]} and expose it only when required.",
        }

    if port in COMMON_ALLOWED_PORTS:
        return {
            **observation,
            "risk": "low",
            "classification": "common-web-service",
            "recommendation": "Confirm the web service is authorized, patched, and properly monitored.",
        }

    if port >= 8000:
        return {
            **observation,
            "risk": "low",
            "classification": "high-numbered-open-port",
            "recommendation": "Verify whether this high-numbered open port is required for the lab or application.",
        }

    return {
        **observation,
        "risk": "low",
        "classification": "open-port-review",
        "recommendation": "Review whether this open port is expected and documented.",
    }


def analyze_port_observations(observations):
    return [classify_port_observation(observation) for observation in observations]


def summarize_port_results(results):
    summary = {
        "total": len(results),
        "open": 0,
        "closed_or_filtered": 0,
        "medium_risk": 0,
        "low_risk": 0,
        "info_risk": 0,
    }

    for result in results:
        if result["state"] == "open":
            summary["open"] += 1
        else:
            summary["closed_or_filtered"] += 1

        if result["risk"] == "medium":
            summary["medium_risk"] += 1
        elif result["risk"] == "low":
            summary["low_risk"] += 1
        else:
            summary["info_risk"] += 1

    return summary


def get_port_analysis_severity(summary):
    if summary["medium_risk"] >= 3:
        return "high"

    if summary["medium_risk"] >= 1:
        return "medium"

    if summary["low_risk"] >= 1:
        return "low"

    return "info"


def build_port_evidence(results, summary):
    evidence = [
        f"Total port observations: {summary['total']}",
        f"Open ports: {summary['open']}",
        f"Closed or filtered ports: {summary['closed_or_filtered']}",
        f"Medium risk observations: {summary['medium_risk']}",
        f"Low risk observations: {summary['low_risk']}",
    ]

    for result in results:
        evidence.append(
            f"port={result['port']}/{result['protocol']} state={result['state']} "
            f"service={result['service']} classification={result['classification']} risk={result['risk']}"
        )

    return evidence


def build_port_recommendations(results):
    recommendations = [
        "Review open ports against the authorized lab scope.",
        "Document why each open service is required.",
        "Restrict sensitive services to trusted networks or local lab ranges.",
    ]

    for result in results:
        if result["risk"] in {"medium", "high"}:
            recommendations.append(result["recommendation"])

    return list(dict.fromkeys(recommendations))


def save_port_finding(results, summary):
    if summary["total"] == 0:
        return None

    finding = create_finding(
        title="TCP port exposure review completed",
        description="Local port observations were reviewed for basic exposure and service risk.",
        severity=get_port_analysis_severity(summary),
        category="network_security",
        source_module="port_checker",
        mitre_technique="N/A",
        evidence=build_port_evidence(results, summary),
        recommendations=build_port_recommendations(results),
    )

    append_finding(finding)
    return finding


def print_port_result(result):
    print(f"- Port: {result['port']}/{result['protocol']}")
    print(f"  State: {result['state']}")
    print(f"  Service: {result['service']}")
    print(f"  Classification: {result['classification']}")
    print(f"  Risk: {result['risk']}")
    print(f"  Recommendation: {result['recommendation']}")


def print_port_summary(summary):
    print("Port observation summary:")
    print(f"- Total: {summary['total']}")
    print(f"- Open: {summary['open']}")
    print(f"- Closed or filtered: {summary['closed_or_filtered']}")
    print(f"- Medium risk: {summary['medium_risk']}")
    print(f"- Low risk: {summary['low_risk']}")
    print(f"- Info risk: {summary['info_risk']}")


def run_port_checker():
    print_section_title("Authorized TCP Port Checker")
    print("This module reviews local port observation samples.")
    print("It does not scan hosts, connect to services, or touch real targets.")
    print()

    observations = load_port_observations_from_file()

    if not observations:
        print("No port observations were found.")
        return

    results = analyze_port_observations(observations)
    summary = summarize_port_results(results)

    for result in results:
        print_port_result(result)
        print()

    print_port_summary(summary)
    print()
    print(f"Severity estimate: {get_port_analysis_severity(summary)}")
    print()

    answer = input("Save port exposure review as a local finding? (y/n): ").strip().lower()

    if answer == "y":
        save_port_finding(results, summary)
        print("Port exposure finding saved to local findings store.")
    else:
        print("Port exposure finding was not saved.")