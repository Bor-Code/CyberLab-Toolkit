import json
from pathlib import Path

from core.constants import DEFAULT_FINDINGS_PATH
from core.finding import Finding
from core.risk_score import summarize_risk


def get_settings_findings_path():
    try:
        from core.settings import get_default_findings_path

        return get_default_findings_path()
    except Exception:
        return DEFAULT_FINDINGS_PATH


def can_save_results():
    try:
        from core.settings import is_save_results_enabled

        return is_save_results_enabled()
    except Exception:
        return True


def get_path(path):
    if path is None:
        return get_settings_findings_path()

    return Path(path)


def ensure_parent_directory(path):
    target = get_path(path)
    target.parent.mkdir(parents=True, exist_ok=True)


def load_findings(path=None):
    target = get_path(path)

    if not target.exists():
        return []

    try:
        raw_data = json.loads(target.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []

    if not isinstance(raw_data, list):
        return []

    return [Finding.from_dict(item) for item in raw_data if isinstance(item, dict)]


def save_findings(findings, path=None):
    if not can_save_results():
        return get_path(path)

    target = get_path(path)
    ensure_parent_directory(target)

    data = []

    for finding in findings:
        if isinstance(finding, Finding):
            data.append(finding.to_dict())
        elif isinstance(finding, dict):
            data.append(finding)

    target.write_text(
        json.dumps(data, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    return target


def append_finding(finding, path=None):
    if not can_save_results():
        return finding

    findings = load_findings(path)
    findings.append(finding)
    save_findings(findings, path)

    return finding


def clear_findings(path=None):
    target = get_path(path)
    ensure_parent_directory(target)
    target.write_text("[]", encoding="utf-8")

    return target


def get_findings_summary(path=None):
    findings = load_findings(path)
    return summarize_risk(findings)