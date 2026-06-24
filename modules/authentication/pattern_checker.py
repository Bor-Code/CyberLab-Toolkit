import getpass

from app.banner import print_section_title
from core.finding import create_finding
from core.report_store import append_finding


COMMON_WORDS = {
    "password",
    "admin",
    "user",
    "login",
    "welcome",
    "qwerty",
    "letmein",
    "test",
    "guest",
}

NUMBER_PATTERNS = {
    "123",
    "1234",
    "12345",
    "123456",
    "111",
    "000",
    "2024",
    "2025",
    "2026",
}

KEYBOARD_PATTERNS = {
    "qwerty",
    "asdf",
    "zxcv",
    "qaz",
    "wsx",
}


def contains_common_word(password):
    lowered_password = password.lower()

    for word in COMMON_WORDS:
        if word in lowered_password:
            return word

    return None


def contains_number_pattern(password):
    for pattern in NUMBER_PATTERNS:
        if pattern in password:
            return pattern

    return None


def contains_keyboard_pattern(password):
    lowered_password = password.lower()

    for pattern in KEYBOARD_PATTERNS:
        if pattern in lowered_password:
            return pattern

    return None


def contains_repeated_sequence(password):
    if len(password) < 3:
        return None

    for index in range(len(password) - 2):
        current = password[index]

        if current == password[index + 1] == password[index + 2]:
            return current * 3

    return None


def analyze_password_patterns(password):
    pattern_findings = []

    common_word = contains_common_word(password)
    if common_word:
        pattern_findings.append(f"Contains common word pattern: {common_word}")

    number_pattern = contains_number_pattern(password)
    if number_pattern:
        pattern_findings.append(f"Contains predictable number pattern: {number_pattern}")

    keyboard_pattern = contains_keyboard_pattern(password)
    if keyboard_pattern:
        pattern_findings.append(f"Contains keyboard pattern: {keyboard_pattern}")

    repeated_sequence = contains_repeated_sequence(password)
    if repeated_sequence:
        pattern_findings.append(f"Contains repeated sequence: {repeated_sequence}")

    if password.isdigit():
        pattern_findings.append("Password contains only digits.")

    if password.isalpha():
        pattern_findings.append("Password contains only letters.")

    if password.lower() == password or password.upper() == password:
        pattern_findings.append("Password does not use mixed letter casing.")

    return pattern_findings


def save_pattern_finding(pattern_findings):
    if not pattern_findings:
        return None

    finding = create_finding(
        title="Common password pattern detected",
        description="The tested password contains one or more predictable patterns. The password value itself is not stored.",
        severity="medium",
        category="authentication",
        source_module="pattern_checker",
        mitre_technique="T1110",
        evidence=pattern_findings,
        recommendations=[
            "Avoid common words and predictable number sequences.",
            "Avoid keyboard patterns such as qwerty or asdf.",
            "Avoid repeated characters.",
            "Use long and unique passphrases.",
            "Use a password manager.",
        ],
    )

    append_finding(finding)
    return finding


def run_pattern_checker():
    print_section_title("Common Password Pattern Checker")
    print("This module checks for common password patterns locally.")
    print("The entered password is not displayed and is not stored.")
    print()

    password = getpass.getpass("Enter password to check: ")

    if not password:
        print("No password entered.")
        return

    pattern_findings = analyze_password_patterns(password)

    print()
    if pattern_findings:
        print("Detected patterns:")

        for item in pattern_findings:
            print(f"- {item}")
    else:
        print("No obvious common password patterns detected.")

    finding = save_pattern_finding(pattern_findings)

    print()
    if finding:
        print("Finding saved to local findings store.")
    else:
        print("No risky finding was created.")