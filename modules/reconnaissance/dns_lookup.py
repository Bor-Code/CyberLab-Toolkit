from pathlib import Path
import ipaddress

from app.banner import print_section_title
from core.finding import create_finding
from core.report_store import append_finding


DEFAULT_DNS_SAMPLE_PATH = Path("samples/dns_records.txt")

COMMON_RECORD_TYPES = {
    "A",
    "AAAA",
    "CNAME",
    "MX",
    "TXT",
    "NS",
}

SOCIAL_ENGINEERING_KEYWORDS = {
    "login",
    "secure",
    "verify",
    "update",
    "payment",
    "bank",
    "invoice",
    "account",
}


def parse_int(value, default=0):
    try:
        return int(str(value).strip())
    except ValueError:
        return default


def load_dns_records(path=DEFAULT_DNS_SAMPLE_PATH):
    target = Path(path)

    if not target.exists():
        return []

    records = []

    for line in target.read_text(encoding="utf-8").splitlines():
        cleaned_line = line.strip()

        if not cleaned_line:
            continue

        if cleaned_line.startswith("#"):
            continue

        parts = [part.strip() for part in cleaned_line.split(",", 4)]

        if len(parts) < 5:
            continue

        records.append(
            {
                "record_type": parts[0].upper(),
                "name": parts[1].lower(),
                "value": parts[2],
                "ttl": parse_int(parts[3]),
                "notes": parts[4],
            }
        )

    return records


def parse_ip_address(value):
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def has_social_engineering_keyword(name):
    lowered_name = name.lower()
    return [keyword for keyword in SOCIAL_ENGINEERING_KEYWORDS if keyword in lowered_name]


def classify_dns_record(record):
    record_type = record["record_type"]
    name = record["name"]
    value = record["value"]
    ttl = record["ttl"]
    notes = []
    score = 0

    if record_type not in COMMON_RECORD_TYPES:
        notes.append("Uncommon DNS record type.")
        score += 1

    if ttl <= 60:
        notes.append("Low TTL value may indicate fast-changing DNS records.")
        score += 2

    keywords = has_social_engineering_keyword(name)

    if keywords:
        notes.append("DNS name contains social engineering keyword.")
        score += 2

    if record_type in {"A", "AAAA"}:
        ip_address = parse_ip_address(value)

        if not ip_address:
            notes.append("IP address value could not be parsed.")
            score += 2
        elif ip_address.is_private:
            notes.append("Record points to a private/local IP address.")
        elif ip_address.is_loopback:
            notes.append("Record points to loopback address.")
            score += 1
        elif ip_address.is_reserved:
            notes.append("Record points to reserved documentation or special-use IP space.")
            score += 1
        else:
            notes.append("Record points to a public IP address.")
            score += 2

    if record_type == "CNAME":
        if value.lower() == name.lower():
            notes.append("CNAME points to itself.")
            score += 3
        else:
            notes.append("CNAME alias recorded for review.")

    if record_type == "MX":
        notes.append("Mail exchange record recorded for review.")

    if record_type == "TXT":
        lowered_value = value.lower()

        if "spf1" in lowered_value:
            notes.append("SPF policy detected.")

        if "dmarc1" in lowered_value:
            notes.append("DMARC policy detected.")

            if "p=none" in lowered_value:
                notes.append("DMARC policy is monitoring-only.")
                score += 1

        if "spf1" not in lowered_value and "dmarc1" not in lowered_value:
            notes.append("TXT record should be reviewed manually.")
            score += 1

    if record_type == "NS":
        notes.append("Nameserver record recorded for review.")

    if not notes:
        notes.append("DNS record recorded with no suspicious pattern.")

    if score >= 5:
        risk = "medium"
        classification = "dns-record-needs-review"
    elif score >= 2:
        risk = "low"
        classification = "dns-record-review"
    else:
        risk = "info"
        classification = "dns-record-documented"

    return {
        "record_type": record_type,
        "name": name,
        "value": value,
        "ttl": ttl,
        "classification": classification,
        "risk": risk,
        "score": score,
        "keywords": keywords,
        "notes": notes,
        "recommendation": get_dns_recommendation(classification),
    }


def get_dns_recommendation(classification):
    if classification == "dns-record-needs-review":
        return "Review this DNS record in an authorized environment and verify ownership and purpose."

    if classification == "dns-record-review":
        return "Document this DNS record and validate whether the pattern is expected."

    return "No immediate action required beyond documentation."


def analyze_dns_records(records):
    return [classify_dns_record(record) for record in records]


def summarize_dns_records(results):
    summary = {
        "total": len(results),
        "medium_risk": 0,
        "low_risk": 0,
        "info_risk": 0,
        "a_records": 0,
        "aaaa_records": 0,
        "cname_records": 0,
        "mx_records": 0,
        "txt_records": 0,
        "ns_records": 0,
        "low_ttl_records": 0,
        "keyword_records": 0,
    }

    for result in results:
        if result["risk"] == "medium":
            summary["medium_risk"] += 1
        elif result["risk"] == "low":
            summary["low_risk"] += 1
        else:
            summary["info_risk"] += 1

        if result["record_type"] == "A":
            summary["a_records"] += 1
        elif result["record_type"] == "AAAA":
            summary["aaaa_records"] += 1
        elif result["record_type"] == "CNAME":
            summary["cname_records"] += 1
        elif result["record_type"] == "MX":
            summary["mx_records"] += 1
        elif result["record_type"] == "TXT":
            summary["txt_records"] += 1
        elif result["record_type"] == "NS":
            summary["ns_records"] += 1

        if result["ttl"] <= 60:
            summary["low_ttl_records"] += 1

        if result["keywords"]:
            summary["keyword_records"] += 1

    return summary


def get_dns_lookup_severity(summary):
    if summary["medium_risk"] >= 2:
        return "medium"

    if summary["medium_risk"] == 1:
        return "low"

    if summary["low_risk"] >= 1:
        return "low"

    return "info"


def build_dns_evidence(results, summary):
    evidence = [
        f"Total DNS records reviewed: {summary['total']}",
        f"Medium risk records: {summary['medium_risk']}",
        f"Low risk records: {summary['low_risk']}",
        f"Low TTL records: {summary['low_ttl_records']}",
        f"Keyword records: {summary['keyword_records']}",
        f"A records: {summary['a_records']}",
        f"AAAA records: {summary['aaaa_records']}",
        f"CNAME records: {summary['cname_records']}",
        f"MX records: {summary['mx_records']}",
        f"TXT records: {summary['txt_records']}",
        f"NS records: {summary['ns_records']}",
    ]

    for result in results:
        evidence.append(
            f"type={result['record_type']} name={result['name']} value={result['value']} "
            f"ttl={result['ttl']} risk={result['risk']} score={result['score']}"
        )

    return evidence


def build_dns_recommendations(results):
    recommendations = [
        "Review DNS records only for domains you own or are authorized to analyze.",
        "Document low TTL records and verify whether fast-changing DNS is expected.",
        "Review DNS names containing login, secure, verify, update, payment, bank, or invoice keywords.",
        "Do not perform unauthorized DNS enumeration against real targets.",
    ]

    for result in results:
        if result["risk"] in {"medium", "low"}:
            recommendations.append(result["recommendation"])

    return list(dict.fromkeys(recommendations))


def save_dns_lookup_finding(results, summary):
    if summary["total"] == 0:
        return None

    finding = create_finding(
        title="Safe DNS record review completed",
        description="Local sample DNS records were reviewed for defensive reconnaissance practice.",
        severity=get_dns_lookup_severity(summary),
        category="reconnaissance",
        source_module="dns_lookup",
        mitre_technique="N/A",
        evidence=build_dns_evidence(results, summary),
        recommendations=build_dns_recommendations(results),
    )

    append_finding(finding)
    return finding


def print_dns_result(result):
    print(f"- Type: {result['record_type']}")
    print(f"  Name: {result['name']}")
    print(f"  Value: {result['value']}")
    print(f"  TTL: {result['ttl']}")
    print(f"  Classification: {result['classification']}")
    print(f"  Risk: {result['risk']}")
    print(f"  Score: {result['score']}")

    if result["keywords"]:
        print(f"  Keywords: {', '.join(result['keywords'])}")
    else:
        print("  Keywords: none")

    print("  Notes:")

    for note in result["notes"]:
        print(f"  - {note}")

    print(f"  Recommendation: {result['recommendation']}")


def print_dns_summary(summary):
    print("DNS record review summary:")
    print(f"- Total records: {summary['total']}")
    print(f"- Medium risk: {summary['medium_risk']}")
    print(f"- Low risk: {summary['low_risk']}")
    print(f"- Info risk: {summary['info_risk']}")
    print(f"- Low TTL records: {summary['low_ttl_records']}")
    print(f"- Keyword records: {summary['keyword_records']}")
    print(f"- A records: {summary['a_records']}")
    print(f"- AAAA records: {summary['aaaa_records']}")
    print(f"- CNAME records: {summary['cname_records']}")
    print(f"- MX records: {summary['mx_records']}")
    print(f"- TXT records: {summary['txt_records']}")
    print(f"- NS records: {summary['ns_records']}")


def run_dns_lookup():
    print_section_title("Basic DNS Lookup")
    print("This module reviews safe local sample DNS records.")
    print("It does not perform live DNS lookups, query external resolvers, or enumerate real domains.")
    print()

    records = load_dns_records()

    if not records:
        print("No local DNS sample records were found.")
        return

    results = analyze_dns_records(records)
    summary = summarize_dns_records(results)

    for result in results:
        print_dns_result(result)
        print()

    print_dns_summary(summary)
    print()
    print(f"Severity estimate: {get_dns_lookup_severity(summary)}")
    print()

    answer = input("Save DNS record review as a local finding? (y/n): ").strip().lower()

    if answer == "y":
        save_dns_lookup_finding(results, summary)
        print("DNS record finding saved to local findings store.")
    else:
        print("DNS record finding was not saved.")