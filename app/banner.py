APP_NAME = "CyberLab Toolkit"
APP_SUBTITLE = "Educational Red Team & Blue Team Lab Platform"


def print_banner():
    print("=" * 70)
    print(f"{APP_NAME:^70}")
    print(f"{APP_SUBTITLE:^70}")
    print("=" * 70)
    print("Authorized lab use and cybersecurity education only.")
    print()


def print_section_title(title):
    print()
    print("-" * 70)
    print(title)
    print("-" * 70)