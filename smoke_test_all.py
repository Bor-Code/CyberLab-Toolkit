import builtins
import traceback
from contextlib import redirect_stdout
from io import StringIO


from modules.reconnaissance.network_discovery import run_network_discovery
from modules.reconnaissance.dns_lookup import run_dns_lookup
from modules.reconnaissance.subdomain_simulator import run_subdomain_simulator
from modules.reconnaissance.recon_report import run_recon_report

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

from app.router import show_current_config
from app.router import change_default_report_path
from app.router import change_save_results_setting
from app.router import reset_settings_to_default
from app.router import show_legal_notice


TESTS = [
    {
        "menu": "1 - Reconnaissance Lab",
        "name": "1.1 Local Network Device Discovery",
        "function": run_network_discovery,
        "inputs": ["n"],
    },
    {
        "menu": "1 - Reconnaissance Lab",
        "name": "1.2 Basic DNS Lookup",
        "function": run_dns_lookup,
        "inputs": ["n"],
    },
    {
        "menu": "1 - Reconnaissance Lab",
        "name": "1.3 Subdomain Wordlist Simulator",
        "function": run_subdomain_simulator,
        "inputs": ["n"],
    },
    {
        "menu": "1 - Reconnaissance Lab",
        "name": "1.4 Save Recon Result",
        "function": run_recon_report,
        "inputs": ["n"],
    },

    {
        "menu": "2 - Web Security Lab",
        "name": "2.1 HTTP Security Header Analyzer",
        "function": run_header_analyzer,
        "inputs": ["n"],
    },
    {
        "menu": "2 - Web Security Lab",
        "name": "2.2 Cookie Security Checker",
        "function": run_cookie_checker,
        "inputs": ["n"],
    },
    {
        "menu": "2 - Web Security Lab",
        "name": "2.3 TLS / HTTPS Basic Check",
        "function": run_tls_checker,
        "inputs": ["n"],
    },
    {
        "menu": "2 - Web Security Lab",
        "name": "2.4 Suspicious URL Structure Analyzer",
        "function": run_url_checker,
        "inputs": ["https://example.test/login?verify=account", "n"],
    },
    {
        "menu": "2 - Web Security Lab",
        "name": "2.5 Web Risk Score Calculator",
        "function": run_web_risk_score,
        "inputs": ["n"],
    },

    {
        "menu": "3 - Password & Authentication Lab",
        "name": "3.1 Password Strength Checker",
        "function": run_password_checker,
        "inputs": ["Password123!", "n"],
    },
    {
        "menu": "3 - Password & Authentication Lab",
        "name": "3.2 Common Password Pattern Checker",
        "function": run_pattern_checker,
        "inputs": ["admin123", "n"],
    },
    {
        "menu": "3 - Password & Authentication Lab",
        "name": "3.3 Hash Type Identifier",
        "function": run_hash_identifier,
        "inputs": ["5d41402abc4b2a76b9719d911017c592", "n"],
    },
    {
        "menu": "3 - Password & Authentication Lab",
        "name": "3.4 Local Brute Force Simulator",
        "function": run_brute_force_simulator,
        "inputs": ["test", "n"],
    },
    {
        "menu": "3 - Password & Authentication Lab",
        "name": "3.5 Login Defense Advisor",
        "function": run_login_defense_advisor,
        "inputs": ["n"],
    },

    {
        "menu": "4 - Network Security Lab",
        "name": "4.1 Authorized TCP Port Checker",
        "function": run_port_checker,
        "inputs": ["127.0.0.1", "80", "n"],
    },
    {
        "menu": "4 - Network Security Lab",
        "name": "4.2 Common Port Explanation",
        "function": run_common_ports,
        "inputs": ["80", "n"],
    },
    {
        "menu": "4 - Network Security Lab",
        "name": "4.3 Localhost Service Check",
        "function": run_localhost_check,
        "inputs": ["n"],
    },
    {
        "menu": "4 - Network Security Lab",
        "name": "4.4 Simple Firewall Recommendation",
        "function": run_firewall_recommendation,
        "inputs": ["80", "n"],
    },
    {
        "menu": "4 - Network Security Lab",
        "name": "4.5 Network Exposure Report",
        "function": run_exposure_report,
        "inputs": ["n"],
    },

    {
        "menu": "5 - Log Analysis & SOC Lab",
        "name": "5.1 Analyze Sample Authentication Logs",
        "function": run_auth_log_analyzer,
        "inputs": ["n"],
    },
    {
        "menu": "5 - Log Analysis & SOC Lab",
        "name": "5.2 Detect Brute Force Pattern",
        "function": run_brute_force_detector,
        "inputs": ["n"],
    },
    {
        "menu": "5 - Log Analysis & SOC Lab",
        "name": "5.3 Detect Suspicious Admin Login",
        "function": run_admin_login_detector,
        "inputs": ["n"],
    },
    {
        "menu": "5 - Log Analysis & SOC Lab",
        "name": "5.4 Detect Repeated 404 Pattern",
        "function": run_repeated_404_detector,
        "inputs": ["n"],
    },
    {
        "menu": "5 - Log Analysis & SOC Lab",
        "name": "5.5 Generate SOC Finding",
        "function": run_soc_finding_generator,
        "inputs": ["n"],
    },

    {
        "menu": "6 - Malware Analysis Helper Lab",
        "name": "6.1 Suspicious File Name Checker",
        "function": run_suspicious_filename_checker,
        "inputs": ["invoice_update.exe", "n"],
    },
    {
        "menu": "6 - Malware Analysis Helper Lab",
        "name": "6.2 File Hash Calculator",
        "function": run_file_hash_calculator,
        "inputs": ["samples/sample_text_file.txt", "n"],
    },
    {
        "menu": "6 - Malware Analysis Helper Lab",
        "name": "6.3 Suspicious Extension Checker",
        "function": run_extension_checker,
        "inputs": ["invoice.pdf.exe", "n"],
    },
    {
        "menu": "6 - Malware Analysis Helper Lab",
        "name": "6.4 Static Indicator Checklist",
        "function": run_static_checklist,
        "inputs": ["n"],
    },
    {
        "menu": "6 - Malware Analysis Helper Lab",
        "name": "6.5 Malware Analysis Report Template",
        "function": run_malware_report_template,
        "inputs": ["n"],
    },

    {
        "menu": "7 - Threat Intelligence Lab",
        "name": "7.1 IOC Format Checker",
        "function": run_ioc_format_checker,
        "inputs": ["8.8.8.8", "n"],
    },
    {
        "menu": "7 - Threat Intelligence Lab",
        "name": "7.2 IP Indicator Classifier",
        "function": run_ip_classifier,
        "inputs": ["8.8.8.8", "n"],
    },
    {
        "menu": "7 - Threat Intelligence Lab",
        "name": "7.3 Domain Indicator Classifier",
        "function": run_domain_classifier,
        "inputs": ["example.test", "n"],
    },
    {
        "menu": "7 - Threat Intelligence Lab",
        "name": "7.4 Hash Indicator Classifier",
        "function": run_hash_classifier,
        "inputs": ["5d41402abc4b2a76b9719d911017c592", "n"],
    },
    {
        "menu": "7 - Threat Intelligence Lab",
        "name": "7.5 IOC Report Builder",
        "function": run_ioc_report_builder,
        "inputs": ["n"],
    },

    {
        "menu": "8 - Reporting Center",
        "name": "8.1 Generate Markdown Report",
        "function": run_markdown_report,
        "inputs": [],
    },
    {
        "menu": "8 - Reporting Center",
        "name": "8.2 Generate SOC Finding Template",
        "function": run_soc_template,
        "inputs": [],
    },
    {
        "menu": "8 - Reporting Center",
        "name": "8.3 Generate Incident Response Checklist",
        "function": run_ir_checklist,
        "inputs": [],
    },
    {
        "menu": "8 - Reporting Center",
        "name": "8.4 View Last Report",
        "function": run_last_report_viewer,
        "inputs": [],
    },
    {
        "menu": "8 - Reporting Center",
        "name": "8.5 Clear Reports",
        "function": run_clear_reports,
        "inputs": ["n"],
    },

    {
        "menu": "9 - Settings",
        "name": "9.1 Show Current Config",
        "function": show_current_config,
        "inputs": [],
    },
    {
        "menu": "9 - Settings",
        "name": "9.2 Change Default Report Path",
        "function": change_default_report_path,
        "inputs": [""],
    },
    {
        "menu": "9 - Settings",
        "name": "9.3 Enable / Disable Save Results",
        "function": change_save_results_setting,
        "inputs": ["y"],
    },
    {
        "menu": "9 - Settings",
        "name": "9.4 Reset Settings",
        "function": reset_settings_to_default,
        "inputs": ["n"],
    },

    {
        "menu": "10 - Legal Notice",
        "name": "10.1 Show Legal Notice",
        "function": show_legal_notice,
        "inputs": [],
    },
]


def fake_input_factory(inputs):
    values = list(inputs)

    def fake_input(prompt=""):
        if values:
            value = values.pop(0)
        else:
            value = "n"

        print(f"{prompt}{value}")
        return value

    return fake_input


def run_one_test(test):
    original_input = builtins.input
    output = StringIO()

    try:
        builtins.input = fake_input_factory(test["inputs"])

        with redirect_stdout(output):
            test["function"]()

        return {
            "name": test["name"],
            "menu": test["menu"],
            "status": "PASS",
            "error": "",
        }

    except Exception:
        return {
            "name": test["name"],
            "menu": test["menu"],
            "status": "FAIL",
            "error": traceback.format_exc(),
        }

    finally:
        builtins.input = original_input


def print_summary(results):
    passed = [result for result in results if result["status"] == "PASS"]
    failed = [result for result in results if result["status"] == "FAIL"]

    print()
    print("=" * 60)
    print("CyberLab Toolkit Smoke Test Summary")
    print("=" * 60)
    print(f"Total tests: {len(results)}")
    print(f"Passed: {len(passed)}")
    print(f"Failed: {len(failed)}")
    print()

    current_menu = None

    for result in results:
        if result["menu"] != current_menu:
            current_menu = result["menu"]
            print()
            print(current_menu)
            print("-" * len(current_menu))

        print(f"[{result['status']}] {result['name']}")

    if failed:
        print()
        print("=" * 60)
        print("Failures")
        print("=" * 60)

        for result in failed:
            print()
            print(result["name"])
            print(result["error"])


def main():
    results = []

    for test in TESTS:
        result = run_one_test(test)
        results.append(result)

    print_summary(results)

    failed_count = len([result for result in results if result["status"] == "FAIL"])

    if failed_count:
        raise SystemExit(1)

    raise SystemExit(0)


if __name__ == "__main__":
    main()