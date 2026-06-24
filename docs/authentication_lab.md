# Password and Authentication Lab

The Password and Authentication Lab provides safe local modules for learning password security, authentication risks, and defensive controls.

This lab does not perform real login attacks, password recovery, credential theft, phishing, or unauthorized brute-force activity.

## Modules

| Module                          | Purpose                                                           |
| ------------------------------- | ----------------------------------------------------------------- |
| Password Strength Checker       | Evaluates password strength locally                               |
| Common Password Pattern Checker | Detects predictable password patterns                             |
| Hash Type Identifier            | Identifies possible hash formats by structure and length          |
| Local Brute Force Simulator     | Demonstrates brute-force logic against a local demo function only |
| Login Defense Advisor           | Provides defensive recommendations against authentication attacks |

## Safety Boundary

The authentication lab is designed for educational and authorized lab use only.

The lab does not support:

* SSH brute forcing
* FTP brute forcing
* Web login brute forcing
* Email account attacks
* Credential theft
* Password cracking
* Phishing
* External authentication attempts

## Password Strength Checker

The password strength checker evaluates a password locally.

It checks for:

* Length
* Uppercase characters
* Lowercase characters
* Digits
* Special characters
* Common password usage
* Repeated characters
* Keyboard patterns

The entered password is not stored.

If the password is weak, the module can generate a local finding without storing the password value.

## Common Password Pattern Checker

The pattern checker identifies predictable password structures such as:

* Common words
* Number sequences
* Keyboard patterns
* Repeated characters
* Digit-only passwords
* Letter-only passwords
* Missing mixed casing

This helps demonstrate why predictable passwords are risky.

## Hash Type Identifier

The hash identifier detects possible hash formats based on length and structure.

Supported indicators include:

* MD5
* SHA1
* SHA256
* SHA512
* bcrypt-like patterns

This module does not crack hashes or recover passwords.

## Local Brute Force Simulator

The brute-force simulator only works against a local demo authentication function.

Demo credentials:

```text
username: admin
password: cyber123
```

The simulator reads candidates from:

```text
samples/demo_wordlist.txt
```

It demonstrates how weak passwords can be guessed when they appear in common wordlists.

It does not connect to real services, networks, websites, or external login systems.

## Login Defense Advisor

The login defense advisor explains defensive controls such as:

* Multi-factor authentication
* Login rate limiting
* Account lockout policies
* Strong password policies
* Authentication logging
* Suspicious login alerting
* Credential reuse protection

## MITRE ATT&CK Mapping

Authentication-related findings may reference:

```text
T1110 - Brute Force
```

This mapping is used for educational and defensive analysis purposes.

## Defensive Lessons

This lab demonstrates that authentication security is not only about password complexity.

Strong defenses should include:

* MFA
* Rate limiting
* Account lockout or progressive delay
* Monitoring failed logins
* Blocking common passwords
* Using password managers
* Avoiding credential reuse
