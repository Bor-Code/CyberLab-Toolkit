from app.banner import print_section_title


def show_main_menu():
    print("[1] Reconnaissance Lab")
    print("[2] Web Security Lab")
    print("[3] Password & Authentication Lab")
    print("[4] Network Security Lab")
    print("[5] Log Analysis & SOC Lab")
    print("[6] Malware Analysis Helper Lab")
    print("[7] Threat Intelligence Lab")
    print("[8] Reporting Center")
    print("[9] Settings")
    print("[10] About / Legal Notice")
    print("[0] Exit")
    print()


def show_reconnaissance_menu():
    print_section_title("Reconnaissance Lab")
    print("[1] Local Network Device Discovery")
    print("[2] Basic DNS Lookup")
    print("[3] Subdomain Wordlist Simulator")
    print("[4] Save Recon Result")
    print("[0] Back")
    print()


def show_web_security_menu():
    print_section_title("Web Security Lab")
    print("[1] HTTP Security Header Analyzer")
    print("[2] Cookie Security Checker")
    print("[3] TLS / HTTPS Basic Check")
    print("[4] Suspicious URL Structure Analyzer")
    print("[5] Web Risk Score Calculator")
    print("[0] Back")
    print()


def show_authentication_menu():
    print_section_title("Password & Authentication Lab")
    print("[1] Password Strength Checker")
    print("[2] Common Password Pattern Checker")
    print("[3] Hash Type Identifier")
    print("[4] Local Brute Force Simulator")
    print("[5] Login Defense Advisor")
    print("[0] Back")
    print()


def show_network_security_menu():
    print_section_title("Network Security Lab")
    print("[1] Authorized TCP Port Checker")
    print("[2] Common Port Explanation")
    print("[3] Localhost Service Check")
    print("[4] Simple Firewall Recommendation")
    print("[5] Network Exposure Report")
    print("[0] Back")
    print()


def show_soc_lab_menu():
    print_section_title("Log Analysis & SOC Lab")
    print("[1] Analyze Sample Authentication Logs")
    print("[2] Detect Brute Force Pattern")
    print("[3] Detect Suspicious Admin Login")
    print("[4] Detect Repeated 404 Pattern")
    print("[5] Generate SOC Finding")
    print("[0] Back")
    print()


def show_malware_helper_menu():
    print_section_title("Malware Analysis Helper Lab")
    print("[1] Suspicious File Name Checker")
    print("[2] File Hash Calculator")
    print("[3] Suspicious Extension Checker")
    print("[4] Static Indicator Checklist")
    print("[5] Malware Analysis Report Template")
    print("[0] Back")
    print()


def show_threat_intel_menu():
    print_section_title("Threat Intelligence Lab")
    print("[1] IOC Format Checker")
    print("[2] IP Indicator Classifier")
    print("[3] Domain Indicator Classifier")
    print("[4] Hash Indicator Classifier")
    print("[5] IOC Report Builder")
    print("[0] Back")
    print()


def show_reporting_menu():
    print_section_title("Reporting Center")
    print("[1] Generate Markdown Report")
    print("[2] Generate SOC Finding Template")
    print("[3] Generate Incident Response Checklist")
    print("[4] View Last Report")
    print("[5] Clear Reports")
    print("[0] Back")
    print()


def show_settings_menu():
    print_section_title("Settings")
    print("[1] Show Current Config")
    print("[2] Change Default Report Path")
    print("[3] Enable / Disable Save Results")
    print("[4] Reset Settings")
    print("[0] Back")
    print()