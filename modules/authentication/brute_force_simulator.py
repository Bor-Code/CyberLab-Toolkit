from pathlib import Path
from time import sleep

from app.banner import print_section_title
from core.finding import create_finding
from core.report_store import append_finding


DEMO_USERNAME = "admin"
DEMO_PASSWORD = "cyber123"
DEFAULT_WORDLIST_PATH = Path("samples/demo_wordlist.txt")
MAX_ATTEMPTS = 50


def demo_authenticate(username, password):
    return username == DEMO_USERNAME and password == DEMO_PASSWORD


def load_wordlist(path=DEFAULT_WORDLIST_PATH):
    target = Path(path)

    if not target.exists():
        return []

    words = []

    for line in target.read_text(encoding="utf-8").splitlines():
        candidate = line.strip()

        if candidate:
            words.append(candidate)

    return words


def simulate_brute_force(username, wordlist):
    attempts = []

    for index, candidate in enumerate(wordlist, start=1):
        if index > MAX_ATTEMPTS:
            break

        success = demo_authenticate(username, candidate)

        attempts.append(
            {
                "attempt": index,
                "candidate": candidate,
                "success": success,
            }
        )

        if success:
            break

    return attempts


def get_simulation_summary(attempts):
    if not attempts:
        return {
            "total_attempts": 0,
            "success": False,
            "matched_password": None,
        }

    for attempt in attempts:
        if attempt["success"]:
            return {
                "total_attempts": attempt["attempt"],
                "success": True,
                "matched_password": attempt["candidate"],
            }

    return {
        "total_attempts": len(attempts),
        "success": False,
        "matched_password": None,
    }


def save_simulation_finding(summary):
    evidence = [
        f"Demo username: {DEMO_USERNAME}",
        f"Total simulated attempts: {summary['total_attempts']}",
        "Target type: local demo authentication function",
        "No real service, network login, or external target was used.",
    ]

    if summary["success"]:
        evidence.append("The demo password was found in the sample wordlist.")

    finding = create_finding(
        title="Local brute-force simulation completed",
        description="A controlled brute-force simulation was executed against a local demo authentication function.",
        severity="info",
        category="authentication",
        source_module="brute_force_simulator",
        mitre_technique="T1110",
        evidence=evidence,
        recommendations=[
            "Use MFA to reduce the impact of guessed passwords.",
            "Apply login rate limiting.",
            "Use account lockout or progressive delay policies.",
            "Monitor repeated failed login attempts.",
            "Block common passwords and weak password patterns.",
        ],
    )

    append_finding(finding)
    return finding


def print_safety_notice():
    print("Safety boundary:")
    print("- This module does not attack SSH, FTP, websites, emails, or real services.")
    print("- This module only tests a local demo authentication function.")
    print("- The goal is to demonstrate brute-force logic and defensive controls.")
    print()


def run_brute_force_simulator():
    print_section_title("Local Brute Force Simulator")
    print_safety_notice()

    print("Demo credentials:")
    print(f"- Demo username: {DEMO_USERNAME}")
    print("- Demo password: hidden for the first run")
    print()

    username = input("Enter demo username: ").strip()

    if not username:
        print("No username entered.")
        return

    if username != DEMO_USERNAME:
        print("This simulator only supports the local demo username.")
        print(f"Use demo username: {DEMO_USERNAME}")
        return

    wordlist = load_wordlist()

    if not wordlist:
        print(f"Wordlist not found or empty: {DEFAULT_WORDLIST_PATH}")
        return

    print()
    print(f"Loaded wordlist: {DEFAULT_WORDLIST_PATH}")
    print(f"Total candidates: {len(wordlist)}")
    print(f"Maximum simulated attempts: {MAX_ATTEMPTS}")
    print()
    print("Starting local demo simulation...")
    print()

    attempts = simulate_brute_force(username, wordlist)

    for attempt in attempts:
        candidate = attempt["candidate"]
        status = "SUCCESS" if attempt["success"] else "FAILED"

        print(f"[{attempt['attempt']:02}] Trying candidate: {candidate} -> {status}")
        sleep(0.1)

        if attempt["success"]:
            break

    summary = get_simulation_summary(attempts)

    print()
    print("Simulation summary:")
    print(f"- Total attempts: {summary['total_attempts']}")
    print(f"- Success: {summary['success']}")

    if summary["success"]:
        print(f"- Matched demo password: {summary['matched_password']}")
    else:
        print("- Matched demo password: not found")

    print()
    print("Defensive lesson:")
    print("- Weak passwords can be guessed if they appear in common wordlists.")
    print("- Rate limiting, MFA, lockout policies, and monitoring reduce this risk.")

    answer = input("\nSave simulation summary as a local finding? (y/n): ").strip().lower()

    if answer == "y":
        save_simulation_finding(summary)
        print("Simulation finding saved to local findings store.")
    else:
        print("Simulation finding was not saved.")