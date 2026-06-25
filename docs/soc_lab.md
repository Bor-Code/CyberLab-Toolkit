# Log Analysis and SOC Lab

The Log Analysis and SOC Lab provides safe local modules for analyzing sample authentication and web logs.

It is designed for cybersecurity education, SOC practice, defensive detection engineering, and portfolio demonstration.

## Purpose

This lab helps analysts practice:

* Authentication log review
* Failed login analysis
* Brute-force pattern detection
* Suspicious privileged login detection
* Repeated 404 detection
* SOC-style finding generation
* Reporting Center integration

All analysis is performed on local sample log files.

## Modules

| Module                          | Purpose                                                                        |
| ------------------------------- | ------------------------------------------------------------------------------ |
| Authentication Log Analyzer     | Summarizes failed and successful authentication events                         |
| Brute Force Log Detector        | Detects repeated failed login patterns                                         |
| Suspicious Admin Login Detector | Finds privileged logins from suspicious conditions                             |
| Repeated 404 Detector           | Detects repeated 404 responses that may indicate scanning or content discovery |
| SOC Finding Generator           | Correlates SOC detections into one local finding                               |

## Sample Log Files

| File                    | Purpose                      |
| ----------------------- | ---------------------------- |
| `samples/auth_logs.txt` | Sample authentication events |
| `samples/web_logs.txt`  | Sample web access events     |

These files are intentionally small and safe for educational lab use.

## Authentication Log Analyzer

The authentication log analyzer reads local sample authentication logs and summarizes:

* Total events
* Failed logins
* Successful logins
* Failed logins by user
* Failed logins by IP address
* Successful logins by user
* Unique users
* Unique IP addresses

It can optionally save a finding to the local findings store.

## Brute Force Log Detector

The brute-force detector identifies repeated failed authentication patterns.

It detects suspicious activity by grouping failed events by:

* Source IP address
* Username

The module maps brute-force-style activity to:

```text
T1110 - Brute Force
```

## Suspicious Admin Login Detector

The suspicious admin login detector reviews successful privileged account logins.

It checks for:

* Privileged usernames such as `admin` and `root`
* Logins from untrusted IP addresses
* Logins outside expected business hours

The module maps suspicious privileged account usage to:

```text
T1078 - Valid Accounts
```

## Repeated 404 Detector

The repeated 404 detector reads local sample web logs and detects repeated 404 responses from the same source.

This can represent suspicious behavior such as:

* Content discovery
* Admin panel probing
* Sensitive file probing
* Basic web scanning patterns

The module maps this behavior to:

```text
T1595 - Active Scanning
```

## SOC Finding Generator

The SOC finding generator correlates authentication and web log detections into one SOC-style finding.

It combines:

* Authentication summary
* Brute-force detections
* Suspicious admin login detections
* Repeated 404 detections

The generated finding is saved locally and can be converted into a Markdown report by the Reporting Center.

## Reporting Flow

A typical workflow is:

```text
SOC Lab -> Generate SOC Finding -> Reporting Center -> Generate Markdown Report
```

This demonstrates a realistic defensive workflow:

1. Analyze sample logs
2. Detect suspicious patterns
3. Generate structured findings
4. Produce a readable security report

## Safety Boundary

This lab does not perform:

* Real attacks
* Network scanning
* Login attempts
* Exploitation
* Credential theft
* Malware execution
* Unauthorized testing

It only analyzes local sample log files.

## Portfolio Value

This lab demonstrates:

* Defensive log analysis
* SOC triage thinking
* MITRE ATT&CK mapping
* Finding generation
* Report-ready evidence collection
* Safe cybersecurity tooling design
