from pathlib import Path

from app.banner import print_section_title


DEFAULT_SOC_TEMPLATE_PATH = Path("reports/soc_investigation_template.md")


def build_soc_template():
    lines = [
        "# SOC Investigation Report Template",
        "",
        "This template is designed for educational SOC analysis, incident triage, and defensive reporting.",
        "",
        "## 1. Investigation Overview",
        "",
        "| Field | Value |",
        "|---|---|",
        "| Investigation Title |  |",
        "| Analyst |  |",
        "| Date |  |",
        "| Severity |  |",
        "| Status | Open / In Progress / Closed |",
        "| Related System |  |",
        "",
        "## 2. Initial Alert",
        "",
        "- Alert name:",
        "- Alert source:",
        "- Detection time:",
        "- Affected user:",
        "- Affected host:",
        "- Source IP:",
        "- Destination IP:",
        "",
        "## 3. Scope",
        "",
        "- What systems are affected?",
        "- What users are affected?",
        "- What time range is being investigated?",
        "- Is the activity isolated or widespread?",
        "",
        "## 4. Timeline",
        "",
        "| Time | Event | Evidence |",
        "|---|---|---|",
        "|  |  |  |",
        "|  |  |  |",
        "|  |  |  |",
        "",
        "## 5. Evidence Collected",
        "",
        "- Authentication logs:",
        "- Web logs:",
        "- Endpoint logs:",
        "- Firewall logs:",
        "- File hashes:",
        "- Suspicious domains:",
        "- Suspicious IP addresses:",
        "",
        "## 6. Analysis Notes",
        "",
        "- What happened?",
        "- Why is it suspicious?",
        "- What normal behavior was compared?",
        "- What evidence supports the conclusion?",
        "",
        "## 7. MITRE ATT&CK Mapping",
        "",
        "| Technique ID | Technique Name | Reason |",
        "|---|---|---|",
        "| T1110 | Brute Force | Example mapping for repeated authentication attempts |",
        "",
        "## 8. Impact Assessment",
        "",
        "- Was access successful?",
        "- Was data exposed?",
        "- Was malware observed?",
        "- Was privilege escalation observed?",
        "- Was lateral movement observed?",
        "",
        "## 9. Containment Actions",
        "",
        "- Disable suspicious account:",
        "- Block malicious IP/domain:",
        "- Isolate affected host:",
        "- Reset credentials:",
        "- Enable or enforce MFA:",
        "",
        "## 10. Eradication and Recovery",
        "",
        "- Remove malicious files:",
        "- Patch vulnerable systems:",
        "- Restore affected services:",
        "- Verify clean state:",
        "- Monitor for recurrence:",
        "",
        "## 11. Recommendations",
        "",
        "- Improve logging coverage.",
        "- Enable alerting for suspicious authentication behavior.",
        "- Apply rate limiting and account lockout policies.",
        "- Enforce strong password policies.",
        "- Use multi-factor authentication.",
        "- Review firewall and access control rules.",
        "",
        "## 12. Final Analyst Conclusion",
        "",
        "Write the final conclusion here.",
        "",
        "## 13. Lessons Learned",
        "",
        "- What worked well?",
        "- What was missing?",
        "- What should be improved before the next incident?",
        "",
    ]

    return "\n".join(lines)


def write_soc_template(path=DEFAULT_SOC_TEMPLATE_PATH):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(build_soc_template(), encoding="utf-8")

    return target


def run_soc_template():
    print_section_title("SOC Report Template")
    print("This module generates a SOC investigation report template.")
    print("The template is intended for defensive analysis and incident documentation.")
    print()

    output_path = write_soc_template()

    print("SOC investigation template generated successfully.")
    print(f"Output path: {output_path}")