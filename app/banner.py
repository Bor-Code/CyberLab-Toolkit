from colorama import init, Fore, Style

init(autoreset=True, convert=True)

BANNER_WIDTH = 82


def center_text(text):
    return text.center(BANNER_WIDTH)


def print_line(char="=", color=Fore.LIGHTMAGENTA_EX):
    print(color + Style.BRIGHT + char * BANNER_WIDTH)


def print_banner():
    print_line("=")
    print(Fore.LIGHTCYAN_EX + Style.BRIGHT + center_text("CYBERLAB TOOLKIT"))
    print(Fore.LIGHTWHITE_EX + Style.BRIGHT + center_text("Educational Red Team & Blue Team Lab Platform"))
    print_line("-")

    left = Fore.LIGHTRED_EX + Style.BRIGHT + "RED TEAM"
    mid = Fore.LIGHTBLUE_EX + Style.BRIGHT + "BLUE TEAM"
    soc = Fore.LIGHTGREEN_EX + Style.BRIGHT + "SOC"
    intel = Fore.LIGHTYELLOW_EX + Style.BRIGHT + "THREAT INTEL"

    print(center_text(f"{left}   {Fore.WHITE}|   {mid}   {Fore.WHITE}|   {soc}   {Fore.WHITE}|   {intel}"))
    print(Fore.YELLOW + Style.DIM + " " * 56 + "developed by Bor-Code")
    print_line("=")

    print(Fore.LIGHTGREEN_EX + Style.BRIGHT + "[SAFE MODE] " + Fore.WHITE + "Authorized lab use and cybersecurity education only.")
    print()


def print_section_title(title):
    print()
    print_line("-", Fore.LIGHTMAGENTA_EX)
    print(Fore.LIGHTCYAN_EX + Style.BRIGHT + center_text(title))
    print_line("-", Fore.LIGHTMAGENTA_EX)