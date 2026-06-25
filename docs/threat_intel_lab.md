# Threat Intelligence Lab

The Threat Intelligence Lab provides safe local modules for practicing indicator of compromise analysis.

It is designed for cybersecurity education, defensive triage, IOC validation, and portfolio demonstration.

## Purpose

This lab helps analysts practice:

* IOC format identification
* IP indicator classification
* Domain indicator classification
* Hash indicator classification
* IOC summary report generation
* Evidence and recommendation writing
* Reporting workflow integration

All checks are performed on local sample files or manually pasted input.

## Modules

| Module                      | Purpose                                                                                 |
| --------------------------- | --------------------------------------------------------------------------------------- |
| IOC Format Checker          | Identifies basic IOC formats such as IP, domain, URL, and hash                          |
| IP Indicator Classifier     | Classifies IP indicators as public, private, loopback, reserved, multicast, and invalid |
| Domain Indicator Classifier | Classifies domain indicators by structure and investigation context                     |
| Hash Indicator Classifier   | Classifies hash indicators by length, character set, and algorithm pattern              |
| IOC Report Builder          | Builds a local Markdown IOC summary report                                              |

## Sample Files

| File                            | Purpose                  |
| ------------------------------- | ------------------------ |
| `samples/iocs.txt`              | Mixed IOC sample list    |
| `samples/ip_indicators.txt`     | Sample IP indicators     |
| `samples/domain_indicators.txt` | Sample domain indicators |
| `samples/hash_indicators.txt`   | Sample hash indicators   |

These files are intentionally safe and local.

## IOC Format Checker

The IOC Format Checker identifies common indicator formats:

* IPv4
* IPv6
* Domain
* URL
* MD5
* SHA1
* SHA256
* Unknown or unsupported values

It helps clean IOC lists before deeper investigation, enrichment, alerting, or reporting.

## IP Indicator Classifier

The IP classifier reviews local or pasted IP indicators.

It can identify:

* Public IP addresses
* Private IP addresses
* Loopback addresses
* Link-local addresses
* Multicast addresses
* Reserved addresses
* Unspecified addresses
* Invalid values

This helps separate internet-facing indicators from internal or local-only values.

## Domain Indicator Classifier

The domain classifier reviews local or pasted domain indicators.

It can identify:

* Public domains
* Internal or local-style domains
* Punycode domains
* IP values accidentally placed in a domain list
* Invalid domain values
* High subdomain depth
* Suspicious keyword combinations

This helps analysts avoid mixing malformed, local, or misleading values into threat intelligence reports.

## Hash Indicator Classifier

The hash classifier reviews local or pasted hash indicators.

It can identify:

* MD5
* SHA1
* SHA256
* SHA512
* Unknown hash-like values
* Non-hex values
* Malformed hash indicators

The module also notes that MD5 and SHA1 may still appear in IOC workflows but should not be treated as strong cryptographic integrity proof.

## IOC Report Builder

The IOC Report Builder combines local IOC analysis results into a Markdown report.

It summarizes:

* IOC format counts
* IP indicator classification results
* Domain indicator classification results
* Hash indicator classification results
* Invalid or unknown indicator counts
* Defensive recommendations

The report is written to:

```text
reports/ioc_summary_report.md
```

## Reporting Flow

A typical workflow is:

```text
Threat Intelligence Lab -> IOC Report Builder -> Reporting Center -> Generate Markdown Report
```

This demonstrates a defensive workflow:

1. Validate IOC formats
2. Separate IP, domain, URL, and hash indicators
3. Classify suspicious or malformed values
4. Build a local IOC summary report
5. Save findings for reporting

## Safety Boundary

This lab does not perform:

* External threat intelligence API queries
* DNS lookups
* Network scanning
* Exploitation
* Malware execution
* File downloading
* URL visiting
* Credential collection
* Unauthorized testing

It only analyzes local samples or manually provided text.

## Portfolio Value

This lab demonstrates:

* Threat intelligence triage basics
* IOC format validation
* Defensive indicator classification
* Safe local analysis design
* Evidence generation
* Recommendation writing
* Markdown report building
* Integration with a modular cybersecurity CLI platform
