import re

from app.banner import print_section_title
from core.finding import create_finding
from core.report_store import append_finding


HASH_PATTERNS = {
    "MD5": {
        "length": 32,
        "regex": r"^[a-fA-F0-9]{32}$",
        "note": "MD5 is considered cryptographically broken and should not be used for password storage.",
    },
    "SHA1": {
        "length": 40,
        "regex": r"^[a-fA-F0-9]{40}$",
        "note": "SHA1 is considered weak for many security-sensitive use cases.",
    },
    "SHA256": {
        "length": 64,
        "regex": r"^[a-fA-F0-9]{64}$",
        "note": "SHA256 is stronger than MD5/SHA1 but still should not be used alone for password storage.",
    },
    "SHA512": {
        "length": 128,
        "regex": r"^[a-fA-F0-9]{128}$",
        "note": "SHA512 is a strong hash family, but password storage should use slow password hashing algorithms.",
    },
    "bcrypt": {
        "length": None,
        "regex": r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$",
        "note": "bcrypt is designed for password hashing and is generally suitable when configured correctly.",
    },
}


def identify_hash_type(hash_value):
    cleaned_hash = hash_value.strip()
    matches = []

    for hash_name, properties in HASH_PATTERNS.items():
        pattern = properties["regex"]

        if re.match(pattern, cleaned_hash):
            matches.append(
                {
                    "type": hash_name,
                    "length": len(cleaned_hash),
                    "note": properties["note"],
                }
            )

    return matches


def get_hash_security_recommendations(matches):
    if not matches:
        return [
            "Verify that the input is a valid hash value.",
            "Use well-known password hashing algorithms for password storage.",
        ]

    recommendations = []

    for match in matches:
        hash_type = match["type"]

        if hash_type in {"MD5", "SHA1"}:
            recommendations.append(f"Avoid using {hash_type} for security-sensitive storage.")
            recommendations.append("Prefer bcrypt, Argon2, or PBKDF2 for password storage.")
        elif hash_type in {"SHA256", "SHA512"}:
            recommendations.append(f"{hash_type} should not be used alone for password storage.")
            recommendations.append("Use a unique salt and a slow password hashing algorithm.")
        elif hash_type == "bcrypt":
            recommendations.append("Check bcrypt cost factor and password policy configuration.")

    return list(dict.fromkeys(recommendations))


def save_hash_identifier_finding(hash_value, matches):
    if not matches:
        finding = create_finding(
            title="Unknown hash-like value",
            description="The submitted value could not be confidently identified as a known hash format.",
            severity="info",
            category="authentication",
            source_module="hash_identifier",
            mitre_technique="N/A",
            evidence=[
                f"Input length: {len(hash_value.strip())}",
                "No known hash pattern matched.",
            ],
            recommendations=get_hash_security_recommendations(matches),
        )

        append_finding(finding)
        return finding

    weak_types = {"MD5", "SHA1"}
    detected_types = [match["type"] for match in matches]

    if not any(hash_type in weak_types for hash_type in detected_types):
        return None

    finding = create_finding(
        title="Weak hash algorithm indicator",
        description="A weak hash algorithm pattern was identified. The original hash value is not stored.",
        severity="medium",
        category="authentication",
        source_module="hash_identifier",
        mitre_technique="N/A",
        evidence=[
            f"Detected possible hash type: {', '.join(detected_types)}",
            f"Hash length: {len(hash_value.strip())}",
        ],
        recommendations=get_hash_security_recommendations(matches),
    )

    append_finding(finding)
    return finding


def run_hash_identifier():
    print_section_title("Hash Type Identifier")
    print("This module identifies possible hash types based on format and length.")
    print("It does not crack hashes or perform password recovery.")
    print()

    hash_value = input("Enter hash value to identify: ").strip()

    if not hash_value:
        print("No hash value entered.")
        return

    matches = identify_hash_type(hash_value)

    print()
    if matches:
        print("Possible hash type matches:")

        for match in matches:
            print(f"- Type: {match['type']}")
            print(f"  Length: {match['length']}")
            print(f"  Note: {match['note']}")
    else:
        print("No known hash format matched this input.")

    print()
    print("Recommendations:")
    for recommendation in get_hash_security_recommendations(matches):
        print(f"- {recommendation}")

    finding = save_hash_identifier_finding(hash_value, matches)

    print()
    if finding:
        print("Finding saved to local findings store.")
    else:
        print("No risky finding was created.")