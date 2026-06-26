from colorama import init, Fore, Style

init(autoreset=True, convert=True)

BANNER_WIDTH = 72


def center_text(text):
    return text.center(BANNER_WIDTH)


def print_banner():
    print(Fore.MAGENTA + "=" * BANNER_WIDTH)
    print(Fore.CYAN + Style.BRIGHT + center_text("CyberLab Toolkit"))
    print(Fore.YELLOW + Style.BRIGHT + center_text("Educational Red Team & Blue Team Lab Platform"))
    print(Fore.MAGENTA + "=" * BANNER_WIDTH)
    print(Fore.GREEN + "Authorized lab use and cybersecurity education only.")
    print()


def print_section_title(title):
    print()
    print(Fore.MAGENTA + "-" * BANNER_WIDTH)
    print(Fore.CYAN + Style.BRIGHT + center_text(title))
    print(Fore.MAGENTA + "-" * BANNER_WIDTH)