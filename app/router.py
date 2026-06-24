from app.banner import print_banner, print_section_title
from app.input_utils import read_choice, wait_for_enter, print_invalid_choice
from app.menu import (
    show_main_menu,
    show_reconnaissance_menu,
    show_web_security_menu,
    show_authentication_menu,
    show_network_security_menu,
    show_soc_lab_menu,
    show_malware_helper_menu,
    show_threat_intel_menu,
    show_reporting_menu,
    show_settings_menu,
)

from modules.reconnaissance.network_discovery import run_network_discovery
from modules.reconnaissance.dns_lookup import run_dns_lookup
from modules.reconnaissance.subdomain_simulator import run_subdomain_simulator

from modules.web_security.header_analyzer import run_header_analyzer
from modules.web_security.cookie_checker import run_cookie_checker
from modules.web_security.tls_checker import run_tls_checker
from modules.web_security.url_checker import run_url_checker
from modules.web_security.web_risk_score import run_web_risk_score

from modules.authentication.password_checker import run_password_checker
from modules.authentication.pattern_checker import run_pattern_checker
from modules.authentication.hash_identifier import run_hash_identifier
from modules.authentication.brute_force_simulator import run_brute_force_simulator
from modules.authentication.login_defense_advisor import run_login_defense_advisor

from modules.network_security.port_checker import run_port_checker
from modules.network_security.common_ports import run_common_ports
from modules.network_security.localhost_check import run_localhost_check
from modules.network_security.firewall_recommendation import run_firewall_recommendation
from modules.network_security.exposure_report import run_exposure_report

from modules.soc_lab.auth_log_analyzer import run_auth_log_analyzer
from modules.soc_lab.brute_force_detector import run_brute_force_detector
from modules.soc_lab.admin_login_detector import run_admin_login_detector
from modules.soc_lab.repeated_404_detector import run_repeated_404_detector
from modules.soc_lab.soc_finding_generator import run_soc_finding_generator

from modules.malware_helper.suspicious_filename_checker import run_suspicious_filename_checker
from modules.malware_helper.file_hash_calculator import run_file_hash_calculator
from modules.malware_helper.extension_checker import run_extension_checker
from modules.malware_helper.static_checklist import run_static_checklist
from modules.malware_helper.report_template import run_malware_report_template

from modules.threat_intel.ioc_format_checker import run_ioc_format_checker
from modules.threat_intel.ip_classifier import run_ip_classifier
from modules.threat_intel.domain_classifier import run_domain_classifier
from modules.threat_intel.hash_classifier import run_hash_classifier
from modules.threat_intel.ioc_report_builder import run_ioc_report_builder

from modules.reporting.markdown_report import run_markdown_report
from modules.reporting.soc_template import run_soc_template
from modules.reporting.ir_checklist import run_ir_checklist
from modules.reporting.last_report_viewer import run_last_report_viewer
from modules.reporting.clear_reports import run_clear_reports


def start_app():
    while True:
        print_banner()
        show_main_menu()

        choice = read_choice()

        if choice == "1":
            route_reconnaissance_lab()
        elif choice == "2":
            route_web_security_lab()
        elif choice == "3":
            route_authentication_lab()
        elif choice == "4":
            route_network_security_lab()
        elif choice == "5":
            route_soc_lab()
        elif choice == "6":
            route_malware_helper_lab()
        elif choice == "7":
            route_threat_intel_lab()
        elif choice == "8":
            route_reporting_center()
        elif choice == "9":
            route_settings()
        elif choice == "10":
            show_legal_notice()
            wait_for_enter()
        elif choice == "0":
            print("Exiting CyberLab Toolkit.")
            break
        else:
            print_invalid_choice()
            wait_for_enter()


def route_reconnaissance_lab():
    while True:
        show_reconnaissance_menu()
        choice = read_choice()

        if choice == "1":
            run_network_discovery()
        elif choice == "2":
            run_dns_lookup()
        elif choice == "3":
            run_subdomain_simulator()
        elif choice == "4":
            print_placeholder("Save Recon Result")
        elif choice == "0":
            break
        else:
            print_invalid_choice()

        wait_for_enter()


def route_web_security_lab():
    while True:
        show_web_security_menu()
        choice = read_choice()

        if choice == "1":
            run_header_analyzer()
        elif choice == "2":
            run_cookie_checker()
        elif choice == "3":
            run_tls_checker()
        elif choice == "4":
            run_url_checker()
        elif choice == "5":
            run_web_risk_score()
        elif choice == "0":
            break
        else:
            print_invalid_choice()

        wait_for_enter()


def route_authentication_lab():
    while True:
        show_authentication_menu()
        choice = read_choice()

        if choice == "1":
            run_password_checker()
        elif choice == "2":
            run_pattern_checker()
        elif choice == "3":
            run_hash_identifier()
        elif choice == "4":
            run_brute_force_simulator()
        elif choice == "5":
            run_login_defense_advisor()
        elif choice == "0":
            break
        else:
            print_invalid_choice()

        wait_for_enter()


def route_network_security_lab():
    while True:
        show_network_security_menu()
        choice = read_choice()

        if choice == "1":
            run_port_checker()
        elif choice == "2":
            run_common_ports()
        elif choice == "3":
            run_localhost_check()
        elif choice == "4":
            run_firewall_recommendation()
        elif choice == "5":
            run_exposure_report()
        elif choice == "0":
            break
        else:
            print_invalid_choice()

        wait_for_enter()


def route_soc_lab():
    while True:
        show_soc_lab_menu()
        choice = read_choice()

        if choice == "1":
            run_auth_log_analyzer()
        elif choice == "2":
            run_brute_force_detector()
        elif choice == "3":
            run_admin_login_detector()
        elif choice == "4":
            run_repeated_404_detector()
        elif choice == "5":
            run_soc_finding_generator()
        elif choice == "0":
            break
        else:
            print_invalid_choice()

        wait_for_enter()


def route_malware_helper_lab():
    while True:
        show_malware_helper_menu()
        choice = read_choice()

        if choice == "1":
            run_suspicious_filename_checker()
        elif choice == "2":
            run_file_hash_calculator()
        elif choice == "3":
            run_extension_checker()
        elif choice == "4":
            run_static_checklist()
        elif choice == "5":
            run_malware_report_template()
        elif choice == "0":
            break
        else:
            print_invalid_choice()

        wait_for_enter()


def route_threat_intel_lab():
    while True:
        show_threat_intel_menu()
        choice = read_choice()

        if choice == "1":
            run_ioc_format_checker()
        elif choice == "2":
            run_ip_classifier()
        elif choice == "3":
            run_domain_classifier()
        elif choice == "4":
            run_hash_classifier()
        elif choice == "5":
            run_ioc_report_builder()
        elif choice == "0":
            break
        else:
            print_invalid_choice()

        wait_for_enter()


def route_reporting_center():
    while True:
        show_reporting_menu()
        choice = read_choice()

        if choice == "1":
            run_markdown_report()
        elif choice == "2":
            run_soc_template()
        elif choice == "3":
            run_ir_checklist()
        elif choice == "4":
            run_last_report_viewer()
        elif choice == "5":
            run_clear_reports()
        elif choice == "0":
            break
        else:
            print_invalid_choice()

        wait_for_enter()


def route_settings():
    while True:
        show_settings_menu()
        choice = read_choice()

        if choice == "1":
            show_current_config()
        elif choice == "2":
            print_placeholder("Change Default Report Path")
        elif choice == "3":
            print_placeholder("Enable / Disable Save Results")
        elif choice == "4":
            print_placeholder("Reset Settings")
        elif choice == "0":
            break
        else:
            print_invalid_choice()

        wait_for_enter()


def show_legal_notice():
    print_section_title("About / Legal Notice")
    print("CyberLab Toolkit is designed for cybersecurity education, authorized lab testing, and defensive learning.")
    print()
    print("This tool must not be used against systems, networks, services, accounts, or applications without explicit permission.")
    print()
    print("This project does not include:")
    print("- Credential theft")
    print("- Real-service brute force")
    print("- Malware")
    print("- Backdoors")
    print("- Persistence")
    print("- Exploit payloads")
    print("- Destructive actions")
    print()
    print("Every module is designed for safe local labs, controlled samples, or defensive analysis.")


def show_current_config():
    print_section_title("Current Config")
    print("Config viewer will be implemented in a future PR.")
    print("Default safe mode: enabled")
    print("Default target: 127.0.0.1")
    print("Default report path: reports/cyberlab_report.md")


def print_placeholder(module_name):
    print_section_title(module_name)
    print("Status: Planned for a future PR.")