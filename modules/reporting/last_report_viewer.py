from pathlib import Path

from app.banner import print_section_title
from core.settings import get_default_report_path


def get_report_path(report_path=None):
    if report_path is None:
        return get_default_report_path()

    return Path(report_path)


def read_last_report(report_path=None):
    target = get_report_path(report_path)

    if not target.exists():
        return None, target

    content = target.read_text(encoding="utf-8")

    if not content.strip():
        return "", target

    return content, target


def print_report_preview(content, max_lines=120):
    lines = content.splitlines()

    if len(lines) <= max_lines:
        print(content)
        return

    for line in lines[:max_lines]:
        print(line)

    print()
    print(f"... Output truncated. Showing first {max_lines} lines of {len(lines)} total lines.")


def run_last_report_viewer():
    print_section_title("Last Report Viewer")
    print("This module displays the latest generated Markdown report.")

    content, report_path = read_last_report()

    print(f"Default report path: {report_path}")
    print()

    if content is None:
        print("No report file was found.")
        print("Generate a report first from Reporting Center -> Generate Markdown Report.")
        return

    if content == "":
        print(f"Report file exists but is empty: {report_path}")
        return

    print(f"Report path: {report_path}")
    print()
    print_report_preview(content)