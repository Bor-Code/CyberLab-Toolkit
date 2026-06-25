# Reporting Center

The Reporting Center converts local educational lab findings into readable Markdown reports and defensive investigation templates.

It is designed for cybersecurity education, SOC practice, incident documentation, and portfolio demonstration.

## Purpose

CyberLab Toolkit modules can generate local findings in JSON format.

The Reporting Center helps analysts:

* Review saved findings
* Generate Markdown reports
* View the latest report
* Create SOC investigation templates
* Create incident response checklists
* Clean generated local report files

## Modules

| Module                      | Purpose                                            |
| --------------------------- | -------------------------------------------------- |
| Markdown Report Generator   | Builds a Markdown report from saved local findings |
| Last Report Viewer          | Displays the latest generated Markdown report      |
| Clear Reports               | Deletes generated local output files               |
| SOC Report Template         | Generates a SOC investigation report template      |
| Incident Response Checklist | Generates a defensive incident response checklist  |

## Default Paths

| Item                 | Path                                     |
| -------------------- | ---------------------------------------- |
| Findings JSON        | `data/findings.json`                     |
| Main Markdown Report | `reports/cyberlab_report.md`             |
| SOC Template         | `reports/soc_investigation_template.md`  |
| IR Checklist         | `reports/incident_response_checklist.md` |

Generated report files are local lab outputs and are not intended to be committed to Git.

## Markdown Report Generator

The Markdown report generator reads findings from:

```text
data/findings.json
```

It creates:

```text
reports/cyberlab_report.md
```

The generated report includes:

* Safety notice
* Executive summary
* Total findings
* Highest risk score
* Average risk score
* Finding details
* Evidence
* Recommendations
* Defensive follow-up steps

## Last Report Viewer

The last report viewer displays the latest generated Markdown report directly in the terminal.

If the report is too long, the output is truncated to keep the terminal readable.

## Clear Reports

The clear reports module deletes generated local output files such as:

* `data/findings.json`
* `reports/cyberlab_report.md`
* Additional generated Markdown files in the reports directory

It does not delete source code, documentation, or `.gitkeep` files.

## SOC Report Template

The SOC report template helps analysts structure investigations.

It includes sections for:

* Investigation overview
* Initial alert
* Scope
* Timeline
* Evidence collected
* Analysis notes
* MITRE ATT&CK mapping
* Impact assessment
* Containment actions
* Recovery
* Recommendations
* Lessons learned

## Incident Response Checklist

The incident response checklist follows common defensive incident response phases:

* Preparation
* Identification
* Containment
* Eradication
* Recovery
* Lessons learned

It also includes evidence collection and communication checklists.

## Safety Boundary

The Reporting Center does not perform attacks, scanning, exploitation, malware execution, credential theft, or unauthorized testing.

It only works with local educational findings and generated documentation files.

## Portfolio Value

This module demonstrates:

* Structured security reporting
* Finding aggregation
* Analyst-friendly Markdown output
* SOC-style documentation
* Defensive incident response thinking
* Clean separation between generated output and source code
