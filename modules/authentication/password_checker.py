import getpass
import string

from app.banner import print_section_title
from core.finding import create_finding
from core.report_store import append_finding


COMMON_PASSWORDS = {
    "123456",
    "123456789",
    "password",
    "admin",
    "admin123",
    "qwerty",
    "letmein",
    "welcome",
    "iloveyou",
    "abc123",
    "111111",
    "123123",
}

KEYBOARD_PATTERNS = {
    "qwerty",
    "asdf",
    "zxcv",
    "1234",
    "abcd",
}


def has_uppercase(password):
    return any(char.isupper() for char in password)


def has_lowercase(password):
    return any(char.islower() for char in password)


def has_digit(password):
    return any(char.isdigit() for char in password)


def has_special_character(password):
    return any(char in string.punctuation for char in password)


def has_repeated_characters(password):
    if len(password) < 3:
        return False

    for index in range(len(password) - 2):
        if password[index] == password[index + 1] == password[index + 2]:
            return True

    return False


def has_keyboard_pattern(password):
    lowered_password = password.lower()

    for pattern in KEYBOARD_PATTERNS:
        if pattern in lowered_password:
            return True

    return False


def get_strength_label(score):
    if score >= 85:
        return "Very Strong"

    if score >= 70:
        return "Strong"

    if score >= 50:
        return "Medium"

    if score >= 30:
        return "Weak"

    return "Very Weak"


def get_severity_from_score(score):
    if score < 30:
        return "high"

    if score < 50:
        return "medium"

    if score < 70:
        return "low"

    return "info"


def evaluate_password_strength(password):
    score = 0
    positive_checks = []
    warnings = []

    if len(password) >= 16:
        score += 35
        positive_checks.append("Password length is strong.")
    elif len(password) >= 12:
        score += 25
        positive_checks.append("Password length is acceptable.")
    elif len(password) >= 8:
        score += 15
        warnings.append("Password should be at least 12 characters for better security.")
    else:
        warnings.append("Password is too short.")

    if has_uppercase(password):
        score += 10
        positive_checks.append("Contains uppercase letters.")
    else:
        warnings.append("Missing uppercase letters.")

    if has_lowercase(password):
        score += 10
        positive_checks.append("Contains lowercase letters.")
    else:
        warnings.append("Missing lowercase letters.")

    if has_digit(password):
        score += 10
        positive_checks.append("Contains digits.")
    else:
        warnings.append("Missing digits.")

    if has_special_character(password):
        score += 15
        positive_checks.append("Contains special characters.")
    else:
        warnings.append("Missing special characters.")

    if password.lower() in COMMON_PASSWORDS:
        score -= 30
        warnings.append("Password appears in a common password list.")

    if has_repeated_characters(password):
        score -= 10
        warnings.append("Password contains repeated character patterns.")

    if has_keyboard_pattern(password):
        score -= 10
        warnings.append("Password contains a common keyboard or sequence pattern.")

    if score < 0:
        score = 0

    if score > 100:
        score = 100

    return {
        "score": score,
        "strength": get_strength_label(score),
        "positive_checks": positive_checks,
        "warnings": warnings,
    }


def save_password_finding(result):
    if result["score"] >= 70:
        return None

    finding = create_finding(
        title="Weak password policy indicator",
        description="The tested password shows weak or risky characteristics. The password value itself is not stored.",
        severity=get_severity_from_score(result["score"]),
        category="authentication",
        source_module="password_checker",
        mitre_technique="T1110",
        evidence=result["warnings"],
        recommendations=[
            "Use at least 12 to 16 characters.",
            "Combine uppercase, lowercase, digits, and special characters.",
            "Avoid common passwords, keyboard patterns, and repeated characters.",
            "Use a password manager for unique passwords.",
            "Enable multi-factor authentication where possible.",
        ],
    )

    append_finding(finding)
    return finding


def run_password_checker():
    print_section_title("Password Strength Checker")
    print("This module evaluates password strength locally.")
    print("The entered password is not displayed and is not stored.")
    print()

    password = getpass.getpass("Enter password to evaluate: ")

    if not password:
        print("No password entered.")
        return

    result = evaluate_password_strength(password)

    print()
    print(f"Password score: {result['score']}/100")
    print(f"Strength level: {result['strength']}")

    print()
    print("Positive checks:")
    if result["positive_checks"]:
        for item in result["positive_checks"]:
            print(f"- {item}")
    else:
        print("- No positive checks found.")

    print()
    print("Warnings:")
    if result["warnings"]:
        for item in result["warnings"]:
            print(f"- {item}")
    else:
        print("- No major warnings found.")

    finding = save_password_finding(result)

    print()
    if finding:
        print("Finding saved to local findings store.")
    else:
        print("No risky finding was created.")