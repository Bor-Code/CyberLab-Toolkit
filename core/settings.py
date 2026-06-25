import json
from pathlib import Path

from core.constants import DEFAULT_FINDINGS_PATH, DEFAULT_REPORT_PATH, DEFAULT_SAFE_MODE


DEFAULT_SETTINGS_PATH = Path("config/settings.json")

DEFAULT_SETTINGS = {
    "safe_mode": DEFAULT_SAFE_MODE,
    "save_results": True,
    "default_report_path": str(DEFAULT_REPORT_PATH),
    "default_findings_path": str(DEFAULT_FINDINGS_PATH),
    "last_updated_by": "CyberLab Toolkit",
}


def ensure_settings_directory(path=DEFAULT_SETTINGS_PATH):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)


def get_default_settings():
    return dict(DEFAULT_SETTINGS)


def normalize_bool(value):
    if isinstance(value, bool):
        return value

    return str(value).strip().lower() in {
        "true",
        "yes",
        "y",
        "1",
        "enabled",
        "on",
    }


def normalize_path(value, fallback):
    cleaned_value = str(value).strip()

    if not cleaned_value:
        return fallback

    return cleaned_value


def validate_settings(settings):
    defaults = get_default_settings()
    validated = {}

    validated["safe_mode"] = normalize_bool(
        settings.get("safe_mode", defaults["safe_mode"])
    )

    validated["save_results"] = normalize_bool(
        settings.get("save_results", defaults["save_results"])
    )

    validated["default_report_path"] = normalize_path(
        settings.get("default_report_path", defaults["default_report_path"]),
        defaults["default_report_path"],
    )

    validated["default_findings_path"] = normalize_path(
        settings.get("default_findings_path", defaults["default_findings_path"]),
        defaults["default_findings_path"],
    )

    validated["last_updated_by"] = normalize_path(
        settings.get("last_updated_by", defaults["last_updated_by"]),
        defaults["last_updated_by"],
    )

    return validated


def load_settings(path=DEFAULT_SETTINGS_PATH):
    target = Path(path)

    if not target.exists():
        settings = get_default_settings()
        save_settings(settings, target)
        return settings

    try:
        raw_settings = json.loads(target.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        settings = get_default_settings()
        save_settings(settings, target)
        return settings

    if not isinstance(raw_settings, dict):
        settings = get_default_settings()
        save_settings(settings, target)
        return settings

    settings = validate_settings(raw_settings)
    save_settings(settings, target)

    return settings


def save_settings(settings, path=DEFAULT_SETTINGS_PATH):
    target = Path(path)
    ensure_settings_directory(target)
    validated = validate_settings(settings)

    target.write_text(
        json.dumps(validated, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    return validated


def reset_settings(path=DEFAULT_SETTINGS_PATH):
    settings = get_default_settings()
    save_settings(settings, path)
    return settings


def update_setting(key, value, path=DEFAULT_SETTINGS_PATH):
    settings = load_settings(path)

    if key not in DEFAULT_SETTINGS:
        return settings

    settings[key] = value
    return save_settings(settings, path)


def get_default_report_path():
    settings = load_settings()
    return Path(settings["default_report_path"])


def get_default_findings_path():
    settings = load_settings()
    return Path(settings["default_findings_path"])


def is_save_results_enabled():
    settings = load_settings()
    return bool(settings["save_results"])


def is_safe_mode_enabled():
    settings = load_settings()
    return bool(settings["safe_mode"])


def format_settings_lines(settings):
    return [
        f"Safe mode: {settings['safe_mode']}",
        f"Save results: {settings['save_results']}",
        f"Default report path: {settings['default_report_path']}",
        f"Default findings path: {settings['default_findings_path']}",
        f"Last updated by: {settings['last_updated_by']}",
    ]