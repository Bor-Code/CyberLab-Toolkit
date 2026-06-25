from pathlib import Path

from app.banner import print_section_title
from core.constants import DEFAULT_FINDINGS_PATH, DEFAULT_REPORT_PATH


def get_cleanup_targets():
    targets = []

    findings_path = Path(DEFAULT_FINDINGS_PATH)
    report_path = Path(DEFAULT_REPORT_PATH)

    targets.append(findings_path)
    targets.append(report_path)

    reports_dir = report_path.parent

    if reports_dir.exists():
        for item in reports_dir.glob("*.md"):
            if item not in targets:
                targets.append(item)

    return targets


def list_existing_targets(targets):
    existing_targets = []

    for target in targets:
        if target.exists() and target.is_file():
            existing_targets.append(target)

    return existing_targets


def clear_generated_reports():
    targets = get_cleanup_targets()
    existing_targets = list_existing_targets(targets)
    deleted = []

    for target in existing_targets:
        target.unlink()
        deleted.append(target)

    return deleted


def run_clear_reports():
    print_section_title("Clear Generated Reports")
    print("This module removes generated local lab output files.")
    print()
    print("It may delete:")
    print(f"- {DEFAULT_FINDINGS_PATH}")
    print(f"- {DEFAULT_REPORT_PATH}")
    print("- Additional Markdown files inside the reports directory")
    print()
    print("It does not delete source code, documentation, or .gitkeep files.")
    print()

    targets = get_cleanup_targets()
    existing_targets = list_existing_targets(targets)

    if not existing_targets:
        print("No generated report files were found.")
        return

    print("Files that will be deleted:")
    for target in existing_targets:
        print(f"- {target}")

    print()
    answer = input("Continue cleanup? (y/n): ").strip().lower()

    if answer != "y":
        print("Cleanup cancelled.")
        return

    deleted = clear_generated_reports()

    print()
    print("Cleanup completed.")
    print(f"Deleted files: {len(deleted)}")

    for target in deleted:
        print(f"- {target}")