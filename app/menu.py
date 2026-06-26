from colorama import Fore, Style
from app.banner import print_section_title


def print_menu_option(number, label, color):
    print(color + Style.BRIGHT + f"[{number}] " + Fore.WHITE + label)


def show_main_menu():
    print_menu_option("1", "Reconnaissance Lab", Fore.CYAN)
    print_menu_option("2", "Web Security Lab", Fore.MAGENTA)
    print_menu_option("3", "Password & Authentication Lab", Fore.YELLOW)
    print_menu_option("4", "Network Security Lab", Fore.GREEN)
    print_menu_option("5", "Log Analysis & SOC Lab", Fore.BLUE)
    print_menu_option("6", "Malware Analysis Helper Lab", Fore.RED)
    print_menu_option("7", "Threat Intelligence Lab", Fore.LIGHTCYAN_EX)
    print_menu_option("8", "Reporting Center", Fore.LIGHTMAGENTA_EX)
    print_menu_option("9", "Settings", Fore.LIGHTYELLOW_EX)
    print_menu_option("10", "About / Legal Notice", Fore.LIGHTGREEN_EX)
    print_menu_option("0", "Exit", Fore.LIGHTRED_EX)
    print()


def show_reconnaissance_menu():
    print_section_title("Reconnaissance Lab")
    print_menu_option("1", "Local Network Device Discovery", Fore.CYAN)
    print_menu_option("2", "Basic DNS Lookup", Fore.MAGENTA)
    print_menu_option("3", "Subdomain Wordlist Simulator", Fore.YELLOW)
    print_menu_option("4", "Save Recon Result", Fore.GREEN)
    print_menu_option("0", "Back", Fore.LIGHTRED_EX)
    print()


def show_web_security_menu():
    print_section_title("Web Security Lab")
    print_menu_option("1", "HTTP Security Header Analyzer", Fore.CYAN)
    print_menu_option("2", "Cookie Security Checker", Fore.MAGENTA)
    print_menu_option("3", "TLS / HTTPS Basic Check", Fore.YELLOW)
    print_menu_option("4", "Suspicious URL Structure Analyzer", Fore.GREEN)
    print_menu_option("5", "Web Risk Score Calculator", Fore.BLUE)
    print_menu_option("0", "Back", Fore.LIGHTRED_EX)
    print()


def show_authentication_menu():
    print_section_title("Password & Authentication Lab")
    print_menu_option("1", "Password Strength Checker", Fore.CYAN)
    print_menu_option("2", "Common Password Pattern Checker", Fore.MAGENTA)
    print_menu_option("3", "Hash Type Identifier", Fore.YELLOW)
    print_menu_option("4", "Local Brute Force Simulator", Fore.GREEN)
    print_menu_option("5", "Login Defense Advisor", Fore.BLUE)
    print_menu_option("0", "Back", Fore.LIGHTRED_EX)
    print()


def show_network_security_menu():
    print_section_title("Network Security Lab")
    print_menu_option("1", "Authorized TCP Port Checker", Fore.CYAN)
    print_menu_option("2", "Common Port Explanation", Fore.MAGENTA)
    print_menu_option("3", "Localhost Service Check", Fore.YELLOW)
    print_menu_option("4", "Simple Firewall Recommendation", Fore.GREEN)
    print_menu_option("5", "Network Exposure Report", Fore.BLUE)
    print_menu_option("0", "Back", Fore.LIGHTRED_EX)
    print()


def show_soc_lab_menu():
    print_section_title("Log Analysis & SOC Lab")
    print_menu_option("1", "Analyze Sample Authentication Logs", Fore.CYAN)
    print_menu_option("2", "Detect Brute Force Pattern", Fore.MAGENTA)
    print_menu_option("3", "Detect Suspicious Admin Login", Fore.YELLOW)
    print_menu_option("4", "Detect Repeated 404 Pattern", Fore.GREEN)
    print_menu_option("5", "Generate SOC Finding", Fore.BLUE)
    print_menu_option("0", "Back", Fore.LIGHTRED_EX)
    print()


def show_malware_helper_menu():
    print_section_title("Malware Analysis Helper Lab")
    print_menu_option("1", "Suspicious File Name Checker", Fore.CYAN)
    print_menu_option("2", "File Hash Calculator", Fore.MAGENTA)
    print_menu_option("3", "Suspicious Extension Checker", Fore.YELLOW)
    print_menu_option("4", "Static Indicator Checklist", Fore.GREEN)
    print_menu_option("5", "Malware Analysis Report Template", Fore.BLUE)
    print_menu_option("0", "Back", Fore.LIGHTRED_EX)
    print()


def show_threat_intel_menu():
    print_section_title("Threat Intelligence Lab")
    print_menu_option("1", "IOC Format Checker", Fore.CYAN)
    print_menu_option("2", "IP Indicator Classifier", Fore.MAGENTA)
    print_menu_option("3", "Domain Indicator Classifier", Fore.YELLOW)
    print_menu_option("4", "Hash Indicator Classifier", Fore.GREEN)
    print_menu_option("5", "IOC Report Builder", Fore.BLUE)
    print_menu_option("0", "Back", Fore.LIGHTRED_EX)
    print()


def show_reporting_menu():
    print_section_title("Reporting Center")
    print_menu_option("1", "Generate Markdown Report", Fore.CYAN)
    print_menu_option("2", "Generate SOC Finding Template", Fore.MAGENTA)
    print_menu_option("3", "Generate Incident Response Checklist", Fore.YELLOW)
    print_menu_option("4", "View Last Report", Fore.GREEN)
    print_menu_option("5", "Clear Reports", Fore.BLUE)
    print_menu_option("0", "Back", Fore.LIGHTRED_EX)
    print()


def show_settings_menu():
    print_section_title("Settings")
    print_menu_option("1", "Show Current Config", Fore.CYAN)
    print_menu_option("2", "Change Default Report Path", Fore.MAGENTA)
    print_menu_option("3", "Enable / Disable Save Results", Fore.YELLOW)
    print_menu_option("4", "Reset Settings", Fore.GREEN)
    print_menu_option("0", "Back", Fore.LIGHTRED_EX)
    print()