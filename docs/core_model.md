# Core Finding and Report Model

CyberLab Toolkit uses a shared core model to represent security findings across all lab modules.

## Purpose

The core model gives every module a consistent way to describe findings, evidence, severity, MITRE mapping, and recommendations.

This makes the project easier to extend and prepares the reporting system for future pull requests.

## Finding Fields

| Field             | Description                                    |
| ----------------- | ---------------------------------------------- |
| `finding_id`      | Unique identifier for the finding              |
| `timestamp`       | UTC timestamp                                  |
| `title`           | Short finding title                            |
| `description`     | Analyst-friendly explanation                   |
| `severity`        | `info`, `low`, `medium`, `high`, or `critical` |
| `category`        | Lab or security category                       |
| `source_module`   | Module that generated the finding              |
| `mitre_technique` | Related MITRE ATT&CK technique if applicable   |
| `evidence`        | List of supporting evidence                    |
| `recommendations` | List of defensive recommendations              |

## Severity Levels

| Severity   | Meaning                                  |
| ---------- | ---------------------------------------- |
| `info`     | Informational observation                |
| `low`      | Low-risk issue                           |
| `medium`   | Issue that may require analyst attention |
| `high`     | Important security finding               |
| `critical` | Severe issue requiring immediate action  |

## Risk Score

The risk score is calculated from:

* Severity
* Evidence count
* Recommendation count
* MITRE ATT&CK mapping presence

The score is normalized between 0 and 100.

## Storage

Findings can be saved as JSON for later reporting.

Default generated path:

```text
data/findings.json
```

Generated JSON files are ignored by Git so lab output does not pollute the repository history.

## Example Finding

```json
{
  "title": "Possible brute force pattern detected",
  "description": "Multiple failed authentication attempts were observed from the same source.",
  "severity": "medium",
  "category": "soc_lab",
  "source_module": "brute_force_detector",
  "mitre_technique": "T1110",
  "evidence": [
    "5 failed login attempts from 192.168.1.20"
  ],
  "recommendations": [
    "Enable MFA",
    "Apply login rate limiting",
    "Monitor repeated failed login attempts"
  ]
}
```

## Safety

This core model does not add offensive functionality.

It only provides data structures, scoring helpers, and storage helpers for safe educational analysis.
