from pathlib import Path

from app.banner import print_section_title


DEFAULT_IR_CHECKLIST_PATH = Path("reports/incident_response_checklist.md")


def build_ir_checklist():
    lines = [
        "# Incident Response Checklist",
        "",
        "This checklist is designed for educational SOC practice and defensive incident response preparation.",
        "",
        "## Phase 1: Preparation",
        "",
        "- Confirm incident response roles and responsibilities.",
        "- Verify contact information for analysts, system owners, and management.",
        "- Ensure logging sources are available and time-synchronized.",
        "- Prepare evidence collection procedures.",
        "- Confirm backup and recovery procedures.",
        "- Review legal, compliance, and reporting requirements.",
        "",
        "## Phase 2: Identification",
        "",
        "- Determine what triggered the alert.",
        "- Identify affected users, hosts, applications, and services.",
        "- Collect initial timestamps and event IDs.",
        "- Review authentication logs, endpoint logs, firewall logs, and web logs.",
        "- Determine whether the event is a true positive, false positive, or needs more investigation.",
        "- Assign an initial severity level.",
        "",
        "## Phase 3: Containment",
        "",
        "- Disable or reset suspicious accounts if needed.",
        "- Isolate affected hosts when appropriate.",
        "- Block malicious IP addresses, domains, or indicators.",
        "- Apply temporary firewall or access control rules.",
        "- Preserve evidence before destructive cleanup actions.",
        "- Communicate containment actions to responsible teams.",
        "",
        "## Phase 4: Eradication",
        "",
        "- Remove malicious files, scripts, or persistence mechanisms if present.",
        "- Patch vulnerable systems.",
        "- Remove unauthorized accounts, keys, or tokens.",
        "- Review scheduled tasks, startup items, and suspicious services.",
        "- Validate that the root cause has been addressed.",
        "",
        "## Phase 5: Recovery",
        "",
        "- Restore systems from clean backups if needed.",
        "- Re-enable services in a controlled manner.",
        "- Monitor affected systems for recurring suspicious activity.",
        "- Confirm users can safely resume normal operations.",
        "- Document recovery time and remaining risks.",
        "",
        "## Phase 6: Lessons Learned",
        "",
        "- Summarize what happened.",
        "- Identify what worked well during the response.",
        "- Identify gaps in detection, logging, communication, or controls.",
        "- Update playbooks and detection rules.",
        "- Improve preventive controls such as MFA, hardening, and patching.",
        "",
        "## Evidence Collection Quick List",
        "",
        "- Alert details",
        "- Timeline of events",
        "- Affected usernames",
        "- Affected hostnames",
        "- Source and destination IP addresses",
        "- File hashes",
        "- Process names",
        "- Command lines",
        "- Network connections",
        "- Screenshots or exported logs",
        "",
        "## Communication Checklist",
        "",
        "- Notify SOC lead or responsible analyst.",
        "- Notify system owner.",
        "- Notify IT operations if containment or recovery is required.",
        "- Notify management if business impact exists.",
        "- Follow legal or compliance reporting requirements when applicable.",
        "",
        "## Final Notes",
        "",
        "This checklist is a defensive learning template. It should be adapted to the organization's actual incident response plan.",
        "",
    ]

    return "\n".join(lines)


def write_ir_checklist(path=DEFAULT_IR_CHECKLIST_PATH):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(build_ir_checklist(), encoding="utf-8")

    return target


def run_ir_checklist():
    print_section_title("Incident Response Checklist")
    print("This module generates an incident response checklist.")
    print("The checklist is intended for defensive SOC practice and incident response preparation.")
    print()

    output_path = write_ir_checklist()

    print("Incident response checklist generated successfully.")
    print(f"Output path: {output_path}")