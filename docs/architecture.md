# Architecture

CyberLab Toolkit uses a modular command-line architecture.

The project is designed to be easy to extend, safe for educational use, and organized around separate cybersecurity learning labs.

## Entry Point

The application starts from:

```text
main.py
```

The `main.py` file only starts the application router:

```python
from app.router import start_app


if __name__ == "__main__":
    start_app()
```

This keeps the entry point clean and separates application startup from menu routing logic.

## App Layer

The `app/` folder contains the command-line interface logic.

| File             | Purpose                                          |
| ---------------- | ------------------------------------------------ |
| `banner.py`      | Prints the application banner and section titles |
| `input_utils.py` | Handles simple input helpers                     |
| `menu.py`        | Contains the main menu and submenu printers      |
| `router.py`      | Routes menu choices to the correct lab modules   |

## Core Layer

The `core/` folder is reserved for shared business logic and models.

Planned components:

| File              | Purpose                         |
| ----------------- | ------------------------------- |
| `finding.py`      | Shared finding data model       |
| `risk_score.py`   | Shared risk scoring helpers     |
| `report_store.py` | Result and report storage logic |
| `constants.py`    | Shared constants                |

## Modules Layer

The `modules/` folder contains the cybersecurity lab modules.

Each lab has its own folder:

```text
modules/
├── reconnaissance/
├── web_security/
├── authentication/
├── network_security/
├── soc_lab/
├── malware_helper/
├── threat_intel/
└── reporting/
```

This structure keeps each topic separated and makes the project easier to maintain.

## Lab Categories

| Lab                           | Purpose                                                                |
| ----------------------------- | ---------------------------------------------------------------------- |
| Reconnaissance Lab            | Local discovery and basic information gathering practice               |
| Web Security Lab              | HTTP header, cookie, TLS, and URL analysis                             |
| Password & Authentication Lab | Password checks, hash identification, and local brute-force simulation |
| Network Security Lab          | Authorized port checks and exposure reporting                          |
| Log Analysis & SOC Lab        | Sample log analysis and SOC finding generation                         |
| Malware Analysis Helper Lab   | Safe file indicator checks and malware analysis templates              |
| Threat Intelligence Lab       | IOC format checks and indicator classification                         |
| Reporting Center              | Markdown reports, SOC templates, and incident response checklists      |

## Safety Design

CyberLab Toolkit is designed around safe educational use.

The project avoids:

* Real credential attacks
* Exploit execution
* Malware behavior
* Persistence
* Destructive actions
* Unauthorized testing logic
* Denial of service features

Every module is intended for local labs, controlled samples, authorized testing, or defensive analysis.
