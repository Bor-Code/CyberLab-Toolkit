from app.banner import print_section_title
from core.finding import create_finding
from core.report_store import append_finding


DEFENSE_CONTROLS = [
    {
        "name": "Multi-Factor Authentication",
        "short_name": "MFA",
        "purpose": "Reduces the impact of stolen or guessed passwords.",
        "recommendation": "Enable MFA for all user accounts, especially administrator and remote access accounts.",
    },
    {
        "name": "Login Rate Limiting",
        "short_name": "Rate Limiting",
        "purpose": "Slows down repeated login attempts from the same source.",
        "recommendation": "Limit repeated failed login attempts per IP address and per user account.",
    },
    {
        "name": "Account Lockout Policy",
        "short_name": "Lockout",
        "purpose": "Prevents unlimited password guessing against the same account.",
        "recommendation": "Lock or delay authentication after several failed login attempts.",
    },
    {
        "name": "Strong Password Policy",
        "short_name": "Password Policy",
        "purpose": "Reduces the chance of weak or predictable passwords.",
        "recommendation": "Require long passwords or passphrases and block common password patterns.",
    },
    {
        "name": "Authentication Logging",
        "short_name": "Logging",
        "purpose": "Helps analysts detect suspicious authentication behavior.",
        "recommendation": "Log failed logins, successful logins, source IPs, usernames, and timestamps.",
    },
    {
        "name": "Suspicious Login Alerting",
        "short_name": "Alerting",
        "purpose": "Detects abnormal login behavior early.",
        "recommendation": "Alert on repeated failed logins, unusual login hours, impossible travel, and admin login anomalies.",
    },
    {
        "name": "Credential Reuse Protection",
        "short_name": "Reuse Protection",
        "purpose": "Reduces risk from leaked or reused credentials.",
        "recommendation": "Encourage unique passwords and use breached-password checks where appropriate.",
    },
]


def get_login_defense_controls():
    return DEFENSE_CONTROLS


def print_defense_controls():
    print()
    print("Recommended defensive controls:")
    print()

    for index, control in enumerate(DEFENSE_CONTROLS, start=1):
        print(f"{index}. {control['name']}")
        print(f"   Purpose: {control['purpose']}")
        print(f"   Recommendation: {control['recommendation']}")
        print()


def build_recommendation_list():
    return [control["recommendation"] for control in DEFENSE_CONTROLS]


def save_defense_advisory():
    finding = create_finding(
        title="Login defense advisory generated",
        description="A defensive authentication checklist was generated for educational and SOC readiness purposes.",
        severity="info",
        category="authentication",
        source_module="login_defense_advisor",
        mitre_technique="T1110",
        evidence=[
            "Authentication defense checklist generated.",
            "Focus area: brute-force resistance, password policy, logging, and alerting.",
        ],
        recommendations=build_recommendation_list(),
    )

    append_finding(finding)
    return finding


def run_login_defense_advisor():
    print_section_title("Login Defense Advisor")
    print("This module provides defensive recommendations against password guessing and brute-force attempts.")
    print("It does not perform attacks, password guessing, or login attempts.")
    print()

    print_defense_controls()

    answer = input("Save this advisory as a local finding? (y/n): ").strip().lower()

    if answer == "y":
        save_defense_advisory()
        print()
        print("Defense advisory saved to local findings store.")
    else:
        print()
        print("Defense advisory was not saved.")