# Web Security Lab

The Web Security Lab provides safe local modules for practicing passive web security analysis.

It is designed for cybersecurity education, defensive assessment, secure configuration review, and portfolio demonstration.

## Purpose

This lab helps analysts practice:

* HTTP security header review
* Cookie security attribute analysis
* TLS / HTTPS observation analysis
* Suspicious URL structure review
* Combined web risk scoring
* Finding generation
* Reporting Center integration

All checks are performed on local sample files or manually pasted input.

## Modules

| Module                            | Purpose                                                         |
| --------------------------------- | --------------------------------------------------------------- |
| HTTP Security Header Analyzer     | Reviews common HTTP response security headers                   |
| Cookie Security Checker           | Checks cookie attributes such as Secure, HttpOnly, and SameSite |
| TLS / HTTPS Basic Check           | Reviews local HTTPS and TLS observation values                  |
| Suspicious URL Structure Analyzer | Detects suspicious URL structure indicators                     |
| Web Risk Score Calculator         | Combines web observations into a single risk score              |

## Sample Files

| File                           | Purpose                               |
| ------------------------------ | ------------------------------------- |
| `samples/http_headers.txt`     | Sample HTTP response headers          |
| `samples/cookies.txt`          | Sample Set-Cookie headers             |
| `samples/tls_https_sample.txt` | Sample TLS / HTTPS observation values |
| `samples/suspicious_urls.txt`  | Sample URL list                       |

These files are intentionally safe and local.

## HTTP Security Header Analyzer

The header analyzer checks for recommended HTTP security headers:

* Content-Security-Policy
* Strict-Transport-Security
* X-Frame-Options
* X-Content-Type-Options
* Referrer-Policy
* Permissions-Policy

It identifies missing headers, explains why they matter, gives recommendations, and can save a finding to the local findings store.

## Cookie Security Checker

The cookie checker parses local or pasted Set-Cookie headers.

It checks:

* Secure
* HttpOnly
* SameSite
* SameSite=None without Secure
* Sensitive cookie name hints such as session, token, auth, csrf, and remember

The module helps identify weak cookie configurations that may increase session or browser-side security risk.

## TLS / HTTPS Basic Check

The TLS / HTTPS checker reviews local observation values such as:

* URL scheme
* TLS version
* Certificate days remaining
* HSTS status
* HTTP to HTTPS redirect status
* Mixed content indicator
* Certificate trust indicator

This module does not connect to remote hosts. It only analyzes provided observation data.

## Suspicious URL Structure Analyzer

The URL analyzer reviews local or pasted URLs for suspicious structure indicators.

It checks for:

* Non-HTTPS URLs
* IP-based hostnames
* Punycode hostnames
* URL shortener domains
* Excessive subdomain depth
* Risky downloadable file extensions
* Path traversal patterns
* Redirect-like parameters
* Encoded characters
* Sensitive keyword combinations

This module does not visit URLs, download files, or scan targets.

## Web Risk Score Calculator

The Web Risk Score Calculator combines the results of the Web Security Lab modules.

It calculates a score based on:

* Missing HTTP security headers
* Cookie security issues
* TLS / HTTPS issues
* Suspicious URL structure indicators

The score is converted into a severity level and can be saved as a local finding.

## Reporting Flow

A typical workflow is:

```text
Web Security Lab -> Web Risk Score Calculator -> Reporting Center -> Generate Markdown Report
```

This demonstrates a defensive workflow:

1. Review local web security observations
2. Detect weak configurations or suspicious structures
3. Convert results into a finding
4. Generate a readable Markdown report

## Safety Boundary

This lab does not perform:

* Real exploitation
* Network scanning
* Credential theft
* Brute-force attacks
* Web crawling
* URL visiting
* File downloading
* Unauthorized testing

It only analyzes local samples or manually provided text.

## Portfolio Value

This lab demonstrates:

* Passive web security review
* OWASP-style configuration thinking
* Secure cookie assessment
* TLS / HTTPS risk reasoning
* URL structure analysis
* Risk scoring
* Evidence and recommendation generation
* Report-ready security findings
