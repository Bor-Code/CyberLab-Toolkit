from pathlib import Path

APP_NAME = "CyberLab Toolkit"
APP_MODE = "educational_lab"

SEVERITY_INFO = "info"
SEVERITY_LOW = "low"
SEVERITY_MEDIUM = "medium"
SEVERITY_HIGH = "high"
SEVERITY_CRITICAL = "critical"

SEVERITY_LEVELS = (
    SEVERITY_INFO,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SEVERITY_HIGH,
    SEVERITY_CRITICAL,
)

SEVERITY_SCORES = {
    SEVERITY_INFO: 10,
    SEVERITY_LOW: 25,
    SEVERITY_MEDIUM: 50,
    SEVERITY_HIGH: 75,
    SEVERITY_CRITICAL: 95,
}

DEFAULT_FINDINGS_PATH = Path("data/findings.json")
DEFAULT_REPORT_PATH = Path("reports/cyberlab_report.md")
DEFAULT_SAFE_MODE = True