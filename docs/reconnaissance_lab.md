# Reconnaissance Lab

The Reconnaissance Lab provides safe, local, and defensive reconnaissance practice modules.

This lab is designed to demonstrate reconnaissance logic without scanning real networks, querying external DNS servers, or enumerating real domains.

## Purpose

The goal of this lab is to practice:

* Local network inventory review
* Safe DNS record review
* Subdomain wordlist simulation
* Reconnaissance report generation
* Evidence-based documentation
* Defensive recommendations

All modules use local sample files and simulated data.

## Modules

| Module                         | Purpose                                                        |
| ------------------------------ | -------------------------------------------------------------- |
| Local Network Device Discovery | Reviews a local sample network inventory                       |
| Basic DNS Lookup               | Reviews local sample DNS records                               |
| Subdomain Wordlist Simulator   | Generates simulated subdomain candidates from a local wordlist |
| Save Recon Result              | Generates a local Markdown reconnaissance report               |

## Sample Files

| File                                | Purpose                             |
| ----------------------------------- | ----------------------------------- |
| `samples/local_network_devices.txt` | Safe local network inventory sample |
| `samples/dns_records.txt`           | Safe DNS record sample              |
| `samples/subdomain_words.txt`       | Simulated subdomain wordlist        |
| `samples/simulated_subdomains.txt`  | Simulated known subdomain list      |

These files are intentionally local and safe.

## Local Network Device Discovery

This module reads a local sample inventory and reviews device information such as:

* IP address
* Hostname
* MAC vendor
* Device type
* Online or offline status
* Notes

The module highlights:

* Unknown device types
* Unknown vendors
* Unknown hostnames
* Router and gateway devices
* IoT devices
* Offline devices

It does not scan real networks, send packets, or connect to devices.

## Basic DNS Lookup

This module reviews local DNS record samples.

Supported record types include:

* A
* AAAA
* CNAME
* MX
* TXT
* NS

The module highlights:

* Low TTL records
* Social engineering keywords
* Public-looking IP records
* Reserved documentation IP ranges
* SPF records
* DMARC records
* Monitoring-only DMARC policies

It does not perform live DNS lookups, query external resolvers, or enumerate real domains.

## Subdomain Wordlist Simulator

This module safely demonstrates subdomain wordlist logic using local files.

It creates simulated candidates such as:

```text id="v2n6z4"
www.example.test
admin.example.test
api.example.test
dev.example.test
backup.example.test
```

The module compares generated candidates against a local simulated known-subdomain list.

It highlights high-interest words such as:

* admin
* login
* portal
* vpn
* dev
* staging
* test
* api
* backup
* db

It does not perform live DNS queries or real subdomain enumeration.

## Save Recon Result

The report writer generates:

```text id="hoxfzx"
reports/reconnaissance_report.md
```

The report includes:

* Safety boundary
* Local network inventory summary
* DNS record review summary
* Subdomain simulation summary
* Defensive recommendations

The report is intended for lab documentation, portfolio review, and analyst-style evidence writing.

## Safety Boundary

This lab does not perform:

* Real network scanning
* Packet sending
* Port scanning
* Live DNS lookup
* External resolver queries
* Real subdomain enumeration
* External API calls
* Unauthorized reconnaissance

Everything is based on local samples and simulated data.

## Portfolio Value

This lab demonstrates:

* Reconnaissance workflow understanding
* Safe lab design
* Local inventory review
* DNS record analysis logic
* Subdomain wordlist logic
* Markdown report generation
* Evidence and recommendation writing
* Defensive security mindset

## Recommended Workflow

1. Review local network inventory.
2. Review local DNS records.
3. Simulate subdomain wordlist generation.
4. Generate a reconnaissance report.
5. Save findings when useful.
6. Use the generated report as a local portfolio artifact.
