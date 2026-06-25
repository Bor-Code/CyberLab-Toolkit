from app.banner import print_section_title
from core.finding import create_finding
from core.report_store import append_finding


COMMON_PORTS = [
    {
        "port": 20,
        "protocol": "tcp",
        "service": "FTP Data",
        "risk": "medium",
        "description": "FTP data transfer channel.",
        "defensive_note": "Prefer SFTP or FTPS when file transfer is required.",
    },
    {
        "port": 21,
        "protocol": "tcp",
        "service": "FTP Control",
        "risk": "medium",
        "description": "Legacy file transfer control channel.",
        "defensive_note": "Avoid exposing FTP to untrusted networks.",
    },
    {
        "port": 22,
        "protocol": "tcp",
        "service": "SSH",
        "risk": "medium",
        "description": "Secure remote administration service.",
        "defensive_note": "Restrict SSH to trusted IP ranges and use key-based authentication.",
    },
    {
        "port": 23,
        "protocol": "tcp",
        "service": "Telnet",
        "risk": "high",
        "description": "Legacy remote administration protocol.",
        "defensive_note": "Disable Telnet and use SSH instead.",
    },
    {
        "port": 25,
        "protocol": "tcp",
        "service": "SMTP",
        "risk": "medium",
        "description": "Mail transfer service.",
        "defensive_note": "Harden mail relay settings and prevent open relay behavior.",
    },
    {
        "port": 53,
        "protocol": "tcp/udp",
        "service": "DNS",
        "risk": "medium",
        "description": "Domain name resolution service.",
        "defensive_note": "Restrict zone transfers and monitor suspicious DNS activity.",
    },
    {
        "port": 80,
        "protocol": "tcp",
        "service": "HTTP",
        "risk": "low",
        "description": "Unencrypted web traffic.",
        "defensive_note": "Redirect HTTP to HTTPS where possible.",
    },
    {
        "port": 110,
        "protocol": "tcp",
        "service": "POP3",
        "risk": "medium",
        "description": "Legacy mailbox retrieval protocol.",
        "defensive_note": "Prefer encrypted mail access protocols.",
    },
    {
        "port": 143,
        "protocol": "tcp",
        "service": "IMAP",
        "risk": "medium",
        "description": "Mailbox access protocol.",
        "defensive_note": "Use encrypted IMAPS and strong authentication.",
    },
    {
        "port": 443,
        "protocol": "tcp",
        "service": "HTTPS",
        "risk": "low",
        "description": "Encrypted web traffic.",
        "defensive_note": "Keep TLS configuration modern and certificates valid.",
    },
    {
        "port": 445,
        "protocol": "tcp",
        "service": "SMB",
        "risk": "high",
        "description": "Windows file sharing and domain service traffic.",
        "defensive_note": "Do not expose SMB to the internet; restrict to trusted internal networks.",
    },
    {
        "port": 1433,
        "protocol": "tcp",
        "service": "MSSQL",
        "risk": "high",
        "description": "Microsoft SQL Server database service.",
        "defensive_note": "Restrict database access and avoid public exposure.",
    },
    {
        "port": 3306,
        "protocol": "tcp",
        "service": "MySQL",
        "risk": "high",
        "description": "MySQL database service.",
        "defensive_note": "Restrict database access to application hosts or trusted networks.",
    },
    {
        "port": 3389,
        "protocol": "tcp",
        "service": "RDP",
        "risk": "high",
        "description": "Remote Desktop Protocol.",
        "defensive_note": "Avoid public RDP exposure; use VPN, MFA, and allowlists.",
    },
    {
        "port": 5432,
        "protocol": "tcp",
        "service": "PostgreSQL",
        "risk": "high",
        "description": "PostgreSQL database service.",
        "defensive_note": "Restrict database access and require strong authentication.",
    },
    {
        "port": 5900,
        "protocol": "tcp",
        "service": "VNC",
        "risk": "high",
        "description": "Remote desktop access service.",
        "defensive_note": "Avoid exposing VNC and require secure tunneling when needed.",
    },
]


def summarize_common_ports():
    summary = {
        "total": len(COMMON_PORTS),
        "high": 0,
        "medium": 0,
        "low": 0,
    }

    for item in COMMON_PORTS:
        summary[item["risk"]] += 1

    return summary


def get_common_ports_severity(summary):
    if summary["high"] >= 5:
        return "medium"

    if summary["high"] >= 1:
        return "low"

    return "info"


def build_common_ports_evidence(summary):
    evidence = [
        f"Total common ports explained: {summary['total']}",
        f"High risk port examples: {summary['high']}",
        f"Medium risk port examples: {summary['medium']}",
        f"Low risk port examples: {summary['low']}",
    ]

    for item in COMMON_PORTS:
        evidence.append(
            f"port={item['port']}/{item['protocol']} service={item['service']} risk={item['risk']}"
        )

    return evidence


def build_common_ports_recommendations():
    return [
        "Document why each exposed service is required.",
        "Avoid exposing administrative and database ports to untrusted networks.",
        "Restrict sensitive services with firewalls, VPNs, allowlists, and strong authentication.",
        "Prefer encrypted protocols such as HTTPS, SSH, SFTP, IMAPS, and SMTPS where appropriate.",
    ]


def save_common_ports_finding(summary):
    finding = create_finding(
        title="Common port defensive review completed",
        description="Common TCP and UDP ports were explained with defensive security considerations.",
        severity=get_common_ports_severity(summary),
        category="network_security",
        source_module="common_ports",
        mitre_technique="N/A",
        evidence=build_common_ports_evidence(summary),
        recommendations=build_common_ports_recommendations(),
    )

    append_finding(finding)
    return finding


def print_common_port(item):
    print(f"- Port: {item['port']}/{item['protocol']}")
    print(f"  Service: {item['service']}")
    print(f"  Risk: {item['risk']}")
    print(f"  Description: {item['description']}")
    print(f"  Defensive note: {item['defensive_note']}")


def print_summary(summary):
    print("Common port summary:")
    print(f"- Total: {summary['total']}")
    print(f"- High risk examples: {summary['high']}")
    print(f"- Medium risk examples: {summary['medium']}")
    print(f"- Low risk examples: {summary['low']}")


def run_common_ports():
    print_section_title("Common Port Explanation")
    print("This module explains common ports and defensive security considerations.")
    print("It does not scan hosts, connect to services, or touch real targets.")
    print()

    for item in COMMON_PORTS:
        print_common_port(item)
        print()

    summary = summarize_common_ports()
    print_summary(summary)
    print()
    print(f"Severity estimate: {get_common_ports_severity(summary)}")
    print()

    answer = input("Save common port review as a local finding? (y/n): ").strip().lower()

    if answer == "y":
        save_common_ports_finding(summary)
        print("Common port review finding saved to local findings store.")
    else:
        print("Common port review finding was not saved.")