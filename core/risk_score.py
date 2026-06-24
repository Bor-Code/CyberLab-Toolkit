from core.constants import (
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_INFO,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SEVERITY_SCORES,
)


def get_value(source, field_name, default=None):
    if isinstance(source, dict):
        return source.get(field_name, default)

    return getattr(source, field_name, default)


def normalize_score(score):
    try:
        value = int(score)
    except (TypeError, ValueError):
        return 0

    if value < 0:
        return 0

    if value > 100:
        return 100

    return value


def score_to_level(score):
    value = normalize_score(score)

    if value >= 90:
        return SEVERITY_CRITICAL

    if value >= 70:
        return SEVERITY_HIGH

    if value >= 40:
        return SEVERITY_MEDIUM

    if value >= 20:
        return SEVERITY_LOW

    return SEVERITY_INFO


def calculate_finding_score(finding):
    severity = str(get_value(finding, "severity", SEVERITY_INFO)).lower()
    evidence = get_value(finding, "evidence", []) or []
    recommendations = get_value(finding, "recommendations", []) or []
    mitre_technique = get_value(finding, "mitre_technique", "N/A")

    base_score = SEVERITY_SCORES.get(severity, SEVERITY_SCORES[SEVERITY_INFO])
    evidence_bonus = min(len(evidence) * 3, 15)
    recommendation_bonus = min(len(recommendations) * 2, 10)
    mitre_bonus = 10 if mitre_technique and mitre_technique != "N/A" else 0

    return normalize_score(base_score + evidence_bonus + recommendation_bonus + mitre_bonus)


def summarize_risk(findings):
    if not findings:
        return {
            "total_findings": 0,
            "highest_score": 0,
            "highest_level": SEVERITY_INFO,
            "average_score": 0,
        }

    scores = [calculate_finding_score(finding) for finding in findings]
    highest_score = max(scores)
    average_score = int(sum(scores) / len(scores))

    return {
        "total_findings": len(findings),
        "highest_score": highest_score,
        "highest_level": score_to_level(highest_score),
        "average_score": average_score,
    }