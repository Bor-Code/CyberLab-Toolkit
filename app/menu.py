from colorama import Fore, Style
from app.banner import print_section_title


def print_menu_option(number, label, description="", color=Fore.CYAN):
    prefix = f"[{number}]"
    label_text = label.ljust(34)

    if description:
        print(
            color
            + Style.BRIGHT
            + prefix.ljust(6)
            + Fore.WHITE
            + Style.BRIGHT
            + label_text
            + Fore.LIGHTBLACK_EX
            + description
        )
    else:
        print(
            color
            + Style.BRIGHT
            + prefix.ljust(6)
            + Fore.WHITE
            + Style.BRIGHT
            + label
        )


def show_main_menu():
    print_menu_option("1", "Reconnaissance Lab", "local recon simulation", Fore.LIGHTCYAN_EX)
    print_menu_option("2", "Web Security Lab", "headers, cookies, TLS, URLs", Fore.LIGHTMAGENTA_EX)
    print_menu_option("3", "Password & Authentication Lab", "passwords, hashes, login defense", Fore.LIGHTYELLOW_EX)
    print_menu_option("4", "Network Security Lab", "ports, localhost, exposure review", Fore.LIGHTGREEN_EX)
    print_menu_option("5", "Log Analysis & SOC Lab", "auth logs, brute force, findings", Fore.LIGHTBLUE_EX)
    print_menu_option("6", "Malware Analysis Helper Lab", "static helper workflow", Fore.LIGHTRED_EX)
    print_menu_option("7", "Threat Intelligence Lab", "IOC classification", Fore.CYAN)
    print_menu_option("8", "Reporting Center", "Markdown reports and templates", Fore.MAGENTA)
    print_menu_option("9", "Settings", "local configuration", Fore.YELLOW)
    print_menu_option("10", "About / Legal Notice", "safe usage boundary", Fore.GREEN)
    print_menu_option("0", "Exit", "close toolkit", Fore.RED)
    print()


def show_reconnaissance_menu():
    print_section_title("Reconnaissance Lab")
    print_menu_option("1", "Local Network Device Discovery", "safe local inventory review", Fore.LIGHTCYAN_EX)
    print_menu_option("2", "Basic DNS Lookup", "local DNS record review", Fore.LIGHTMAGENTA_EX)
    print_menu_option("3", "Subdomain Wordlist Simulator", "simulated wordlist logic", Fore.LIGHTYELLOW_EX)
    print_menu_option("4", "Save Recon Result", "generate recon report", Fore.LIGHTGREEN_EX)
    print_menu_option("0", "Back", "", Fore.RED)
    print()


def show_web_security_menu():
    print_section_title("Web Security Lab")
    print_menu_option("1", "HTTP Security Header Analyzer", "review missing headers", Fore.LIGHTCYAN_EX)
    print_menu_option("2", "Cookie Security Checker", "review cookie flags", Fore.LIGHTMAGENTA_EX)
    print_menu_option("3", "TLS / HTTPS Basic Check", "safe TLS sample review", Fore.LIGHTYELLOW_EX)
    print_menu_option("4", "Suspicious URL Structure Analyzer", "URL pattern review", Fore.LIGHTGREEN_EX)
    print_menu_option("5", "Web Risk Score Calculator", "web risk summary", Fore.LIGHTBLUE_EX)
    print_menu_option("0", "Back", "", Fore.RED)
    print()


def show_authentication_menu():
    print_section_title("Password & Authentication Lab")
    print_menu_option("1", "Password Strength Checker", "basic strength review", Fore.LIGHTCYAN_EX)
    print_menu_option("2", "Common Password Pattern Checker", "detect weak patterns", Fore.LIGHTMAGENTA_EX)
    print_menu_option("3", "Hash Type Identifier", "identify hash format", Fore.LIGHTYELLOW_EX)
    print_menu_option("4", "Local Brute Force Simulator", "safe local simulation", Fore.LIGHTGREEN_EX)
    print_menu_option("5", "Login Defense Advisor", "defensive guidance", Fore.LIGHTBLUE_EX)
    print_menu_option("0", "Back", "", Fore.RED)
    print()


def show_network_security_menu():
    print_section_title("Network Security Lab")
    print_menu_option("1", "Authorized TCP Port Checker", "controlled local check", Fore.LIGHTCYAN_EX)
    print_menu_option("2", "Common Port Explanation", "service meaning review", Fore.LIGHTMAGENTA_EX)
    print_menu_option("3", "Localhost Service Check", "localhost-only review", Fore.LIGHTYELLOW_EX)
    print_menu_option("4", "Simple Firewall Recommendation", "basic hardening notes", Fore.LIGHTGREEN_EX)
    print_menu_option("5", "Network Exposure Report", "local report output", Fore.LIGHTBLUE_EX)
    print_menu_option("0", "Back", "", Fore.RED)
    print()


def show_soc_lab_menu():
    print_section_title("Log Analysis & SOC Lab")
    print_menu_option("1", "Analyze Sample Authentication Logs", "local log review", Fore.LIGHTCYAN_EX)
    print_menu_option("2", "Detect Brute Force Pattern", "failed login pattern", Fore.LIGHTMAGENTA_EX)
    print_menu_option("3", "Detect Suspicious Admin Login", "admin event review", Fore.LIGHTYELLOW_EX)
    print_menu_option("4", "Detect Repeated 404 Pattern", "web log pattern", Fore.LIGHTGREEN_EX)
    print_menu_option("5", "Generate SOC Finding", "analyst-style finding", Fore.LIGHTBLUE_EX)
    print_menu_option("0", "Back", "", Fore.RED)
    print()


def show_malware_helper_menu():
    print_section_title("Malware Analysis Helper Lab")
    print_menu_option("1", "Suspicious File Name Checker", "filename triage", Fore.LIGHTCYAN_EX)
    print_menu_option("2", "File Hash Calculator", "local hash calculation", Fore.LIGHTMAGENTA_EX)
    print_menu_option("3", "Suspicious Extension Checker", "extension review", Fore.LIGHTYELLOW_EX)
    print_menu_option("4", "Static Indicator Checklist", "static review helper", Fore.LIGHTGREEN_EX)
    print_menu_option("5", "Malware Analysis Report Template", "safe report template", Fore.LIGHTBLUE_EX)
    print_menu_option("0", "Back", "", Fore.RED)
    print()


def show_threat_intel_menu():
    print_section_title("Threat Intelligence Lab")
    print_menu_option("1", "IOC Format Checker", "indicator format review", Fore.LIGHTCYAN_EX)
    print_menu_option("2", "IP Indicator Classifier", "IP classification", Fore.LIGHTMAGENTA_EX)
    print_menu_option("3", "Domain Indicator Classifier", "domain classification", Fore.LIGHTYELLOW_EX)
    print_menu_option("4", "Hash Indicator Classifier", "hash classification", Fore.LIGHTGREEN_EX)
    print_menu_option("5", "IOC Report Builder", "indicator report output", Fore.LIGHTBLUE_EX)
    print_menu_option("0", "Back", "", Fore.RED)
    print()


def show_reporting_menu():
    print_section_title("Reporting Center")
    print_menu_option("1", "Generate Markdown Report", "build report from findings", Fore.LIGHTCYAN_EX)
    print_menu_option("2", "Generate SOC Finding Template", "SOC template output", Fore.LIGHTMAGENTA_EX)
    print_menu_option("3", "Generate Incident Response Checklist", "IR checklist output", Fore.LIGHTYELLOW_EX)
    print_menu_option("4", "View Last Report", "preview latest report", Fore.LIGHTGREEN_EX)
    print_menu_option("5", "Clear Reports", "cleanup generated files", Fore.LIGHTBLUE_EX)
    print_menu_option("0", "Back", "", Fore.RED)
    print()


def show_settings_menu():
    print_section_title("Settings")
    print_menu_option("1", "Show Current Config", "view local settings", Fore.LIGHTCYAN_EX)
    print_menu_option("2", "Change Default Report Path", "set report output path", Fore.LIGHTMAGENTA_EX)
    print_menu_option("3", "Enable / Disable Save Results", "toggle local saving", Fore.LIGHTYELLOW_EX)
    print_menu_option("4", "Reset Settings", "restore defaults", Fore.LIGHTGREEN_EX)
    print_menu_option("0", "Back", "", Fore.RED)
    print()