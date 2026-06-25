from pathlib import Path

from app.banner import print_section_title
from core.finding import create_finding
from core.report_store import append_finding


DEFAULT_WORDLIST_PATH = Path("samples/subdomain_words.txt")
DEFAULT_SIMULATED_SUBDOMAINS_PATH = Path("samples/simulated_subdomains.txt")
DEFAULT_BASE_DOMAIN = "example.test"

HIGH_INTEREST_WORDS = {
    "admin",
    "login",
    "portal",
    "vpn",
    "dev",
    "staging",
    "test",
    "api",
    "backup",
    "db",
}

NORMAL_WORDS = {
    "www",
    "mail",
    "cdn",
    "files",
    "support",
}


def load_lines_from_file(path):
    target = Path(path)

    if not target.exists():
        return []

    values = []

    for line in target.read_text(encoding="utf-8").splitlines():
        cleaned_line = line.strip().lower()

        if not cleaned_line:
            continue

        if cleaned_line.startswith("#"):
            continue

        values.append(cleaned_line)

    return values


def load_wordlist(path=DEFAULT_WORDLIST_PATH):
    return load_lines_from_file(path)


def load_simulated_subdomains(path=DEFAULT_SIMULATED_SUBDOMAINS_PATH):
    return set(load_lines_from_file(path))


def clean_word(word):
    cleaned_word = word.strip().lower()
    cleaned_word = cleaned_word.replace(" ", "")
    cleaned_word = cleaned_word.replace("/", "")
    cleaned_word = cleaned_word.replace("\\", "")
    return cleaned_word


def build_candidate_subdomain(word, base_domain=DEFAULT_BASE_DOMAIN):
    cleaned_word = clean_word(word)
    cleaned_base_domain = base_domain.strip().lower()

    if not cleaned_word:
        return ""

    return f"{cleaned_word}.{cleaned_base_domain}"


def classify_subdomain_candidate(word, candidate, simulated_known_subdomains):
    notes = []
    score = 0
    cleaned_word = clean_word(word)

    if not candidate:
        notes.append("Empty candidate skipped.")
        score += 1

    if candidate in simulated_known_subdomains:
        notes.append("Candidate exists in the local simulated subdomain list.")
        score += 1
        discovery_status = "simulated-match"
    else:
        notes.append("Candidate does not exist in the local simulated subdomain list.")
        discovery_status = "simulated-no-match"

    if cleaned_word in HIGH_INTEREST_WORDS:
        notes.append("Word is commonly interesting during authorized recon review.")
        score += 2

    if cleaned_word in NORMAL_WORDS:
        notes.append("Word is a common service or support-style subdomain name.")

    if len(cleaned_word) <= 2:
        notes.append("Very short subdomain word should be reviewed manually.")
        score += 1

    if not notes:
        notes.append("Candidate generated with no notable pattern.")

    if score >= 4:
        risk = "medium"
        classification = "high-interest-candidate"
    elif score >= 2:
        risk = "low"
        classification = "review-candidate"
    else:
        risk = "info"
        classification = "documented-candidate"

    return {
        "word": cleaned_word,
        "candidate": candidate,
        "discovery_status": discovery_status,
        "classification": classification,
        "risk": risk,
        "score": score,
        "notes": notes,
        "recommendation": get_subdomain_recommendation(classification),
    }


def get_subdomain_recommendation(classification):
    if classification == "high-interest-candidate":
        return "Review this simulated candidate carefully in authorized recon documentation."

    if classification == "review-candidate":
        return "Document this candidate and verify whether it is expected in the simulated inventory."

    return "No immediate action required beyond documentation."


def generate_subdomain_candidates(words, base_domain=DEFAULT_BASE_DOMAIN):
    candidates = []

    for word in words:
        candidate = build_candidate_subdomain(word, base_domain)

        if candidate:
            candidates.append(candidate)

    return candidates


def analyze_subdomain_words(words, simulated_known_subdomains, base_domain=DEFAULT_BASE_DOMAIN):
    results = []

    for word in words:
        candidate = build_candidate_subdomain(word, base_domain)

        if not candidate:
            continue

        results.append(
            classify_subdomain_candidate(
                word,
                candidate,
                simulated_known_subdomains,
            )
        )

    return results


def summarize_subdomain_results(results):
    summary = {
        "total": len(results),
        "simulated_matches": 0,
        "simulated_no_matches": 0,
        "medium_risk": 0,
        "low_risk": 0,
        "info_risk": 0,
        "high_interest_words": 0,
    }

    for result in results:
        if result["discovery_status"] == "simulated-match":
            summary["simulated_matches"] += 1
        else:
            summary["simulated_no_matches"] += 1

        if result["risk"] == "medium":
            summary["medium_risk"] += 1
        elif result["risk"] == "low":
            summary["low_risk"] += 1
        else:
            summary["info_risk"] += 1

        if result["word"] in HIGH_INTEREST_WORDS:
            summary["high_interest_words"] += 1

    return summary


def get_subdomain_severity(summary):
    if summary["medium_risk"] >= 2:
        return "medium"

    if summary["medium_risk"] == 1:
        return "low"

    if summary["low_risk"] >= 1:
        return "low"

    return "info"


def build_subdomain_evidence(results, summary):
    evidence = [
        f"Total candidates generated: {summary['total']}",
        f"Simulated matches: {summary['simulated_matches']}",
        f"Simulated no matches: {summary['simulated_no_matches']}",
        f"High interest words: {summary['high_interest_words']}",
        f"Medium risk candidates: {summary['medium_risk']}",
        f"Low risk candidates: {summary['low_risk']}",
    ]

    for result in results:
        evidence.append(
            f"word={result['word']} candidate={result['candidate']} "
            f"status={result['discovery_status']} risk={result['risk']} score={result['score']}"
        )

    return evidence


def build_subdomain_recommendations(results):
    recommendations = [
        "Use subdomain wordlists only in authorized environments.",
        "Do not enumerate real domains without explicit permission.",
        "Treat admin, login, vpn, dev, staging, backup, and db names as high-interest recon notes.",
        "Document simulated matches separately from generated candidates.",
    ]

    for result in results:
        if result["risk"] in {"medium", "low"}:
            recommendations.append(result["recommendation"])

    return list(dict.fromkeys(recommendations))


def save_subdomain_finding(results, summary):
    if summary["total"] == 0:
        return None

    finding = create_finding(
        title="Safe subdomain wordlist simulation completed",
        description="Local wordlist entries were converted into simulated subdomain candidates for authorized recon practice.",
        severity=get_subdomain_severity(summary),
        category="reconnaissance",
        source_module="subdomain_simulator",
        mitre_technique="N/A",
        evidence=build_subdomain_evidence(results, summary),
        recommendations=build_subdomain_recommendations(results),
    )

    append_finding(finding)
    return finding


def print_subdomain_result(result):
    print(f"- Word: {result['word']}")
    print(f"  Candidate: {result['candidate']}")
    print(f"  Simulated status: {result['discovery_status']}")
    print(f"  Classification: {result['classification']}")
    print(f"  Risk: {result['risk']}")
    print(f"  Score: {result['score']}")
    print("  Notes:")

    for note in result["notes"]:
        print(f"  - {note}")

    print(f"  Recommendation: {result['recommendation']}")


def print_subdomain_summary(summary):
    print("Subdomain wordlist simulation summary:")
    print(f"- Total candidates: {summary['total']}")
    print(f"- Simulated matches: {summary['simulated_matches']}")
    print(f"- Simulated no matches: {summary['simulated_no_matches']}")
    print(f"- High interest words: {summary['high_interest_words']}")
    print(f"- Medium risk: {summary['medium_risk']}")
    print(f"- Low risk: {summary['low_risk']}")
    print(f"- Info risk: {summary['info_risk']}")


def run_subdomain_simulator():
    print_section_title("Subdomain Wordlist Simulator")
    print("This module safely simulates subdomain wordlist logic using local files.")
    print("It does not query DNS, enumerate real domains, or contact external systems.")
    print()

    words = load_wordlist()
    simulated_known_subdomains = load_simulated_subdomains()

    if not words:
        print("No local subdomain wordlist entries were found.")
        return

    results = analyze_subdomain_words(
        words,
        simulated_known_subdomains,
        DEFAULT_BASE_DOMAIN,
    )

    summary = summarize_subdomain_results(results)

    for result in results:
        print_subdomain_result(result)
        print()

    print_subdomain_summary(summary)
    print()
    print(f"Severity estimate: {get_subdomain_severity(summary)}")
    print()

    answer = input("Save subdomain simulation as a local finding? (y/n): ").strip().lower()

    if answer == "y":
        save_subdomain_finding(results, summary)
        print("Subdomain simulation finding saved to local findings store.")
    else:
        print("Subdomain simulation finding was not saved.")