# Linux Security Auditor

A Python-based Linux security auditing tool designed to perform automated security checks on a Linux system. The tool evaluates common security configurations, identifies potential security weaknesses, calculates a security score, classifies the overall risk level, and generates a timestamped security audit report.

## Features

- Firewall status auditing
- Open and listening port detection
- User account and sudo privilege auditing
- Critical file permission checks
- World-writable file detection
- SUID and SGID file auditing
- SSH configuration auditing
- Running service enumeration
- System package update checking
- Password policy auditing
- Security risk classification
- Security score calculation
- Security findings and recommendations
- Timestamped security audit reports
- Hostname and tool version information
- Command-line options for version and help
- Error handling for common system and command failures

## Technologies Used

- Python 3
- Linux
- Kali Linux
- Bash/Linux command-line utilities
- `subprocess` for system command execution
- `os` and `stat` for file and permission checks
- `socket` for hostname information
- `datetime` for timestamped reports
- `sys` for command-line argument handling

## Security Checks Performed

The Linux Security Auditor performs the following security checks:

### 1. Firewall Audit

Checks whether the UFW firewall is active and reports the firewall status.

### 2. Open Port Audit

Identifies listening TCP and UDP ports using the `ss` command.

### 3. User Account Audit

Lists regular user accounts and identifies users with sudo privileges.

### 4. File Permission Audit

Checks the permissions of critical system files such as:

- `/etc/passwd`
- `/etc/shadow`

### 5. World-Writable File Audit

Searches selected system directories for files that can be modified by any user.

### 6. SUID/SGID File Audit

Identifies files with SUID and SGID permissions, which can provide elevated privileges when executed.

### 7. SSH Configuration Audit

Checks important SSH settings including:

- Root login
- Password authentication
- Public key authentication
- X11 forwarding

### 8. Running Service Audit

Lists currently running system services to provide visibility into active services.

### 9. Package Update Audit

Checks for available system package updates using the APT package manager.

### 10. Password Policy Audit

Checks password policy settings such as:

- Maximum password age
- Minimum password age
- Password expiration warning period

## Security Scoring

The tool calculates a security score out of 100 based on selected security findings.

| Security Check | Score Deduction |
|---|---:|
| Firewall inactive | -20 |
| Listening ports detected | -10 |
| Available package updates | -5 |
| Maximum password age ≥ 365 days | -10 |
| World-writable files detected | -10 |

### Risk Levels

| Score | Risk Level |
|---|---|
| 90–100 | LOW |
| 70–89 | MEDIUM |
| 50–69 | HIGH |
| Below 50 | CRITICAL |

> **Note:** The scoring system and risk thresholds are project-defined rules used by this tool for demonstration and auditing purposes. They are not a universal industry security standard.

## How It Works

The Linux Security Auditor follows a simple security auditing workflow:

1. The tool starts and collects basic system information.
2. Security checks are performed using Python and Linux system commands.
3. The tool evaluates firewall status, open ports, users, file permissions, SSH configuration, running services, package updates, password policy, world-writable files, and SUID/SGID files.
4. Security findings are recorded with appropriate risk levels.
5. Recommendations are generated for detected security issues.
6. A security score is calculated based on the defined scoring rules.
7. The overall risk level is determined from the security score.
8. A timestamped security audit report is generated in the project directory.

### Audit Workflow

```text
Linux System
     ↓
Security Checks
     ↓
Findings Detection
     ↓
Risk Classification
     ↓
Security Score
     ↓
Recommendations
     ↓
Audit Report
```

## Installation and Usage

### Clone the Repository

```text
git clone https://github.com/nylagouri2003/linux-security-auditor.git
cd linux-security-auditor
```

### Run the Auditor

```text
python3 auditor.py
```

Some security checks require administrator privileges. The tool may request the user's sudo password when necessary.

### Check Tool Version

```text
python3 auditor.py --version
```

Example output:

```text
Linux Security Auditor v1.0.0
```

### Display Help

```text
python3 auditor.py --help
```

Example output:

```text
Linux Security Auditor

Usage:
  python3 auditor.py
  python3 auditor.py --version
  python3 auditor.py --help
```

### Invalid Option Handling

```text
python3 auditor.py --test
```

Example output:

```text
[ERROR] Unknown option: --test
Use --help for available options.
```

## Example Output

```text
LINUX SECURITY AUDITOR

================================
[WARNING] Firewall: INACTIVE (-20)
[PASS] Open Ports: No listening ports detected
[INFO] Regular Users:
wolfy (UID: 1000)
[INFO] Sudo Users:
wolfy
[INFO] File Permission Audit:
[PASS] /etc/passwd: 0o644
[PASS] /etc/shadow: 0o640
[INFO] World-Writable File Audit:
[PASS] No world-writable files detected
[INFO] SUID/SGID File Audit:
[INFO] SUID files detected: 32
[INFO] SGID files detected: 7
[INFO] SSH Configuration Audit:
[PASS] SSH: Root login is not explicitly enabled
[INFO] SSH: Password authentication is not explicitly enabled
[INFO] SSH: Public key authentication is not explicitly enabled
[INFO] SSH: X11 forwarding is enabled
[INFO] Package Update Audit:
[WARNING] 2 package(s) have available updates (-5):
libigc2
libigdfcl2
[INFO] Password Policy Audit:
[WARNING] Maximum password age: 99999 days (-10)

================================
SECURITY SCORE: 65/100
RISK LEVEL: HIGH

[INFO] Security report generated:
security_report_YYYY-MM-DD_HH-MM-SS.txt
```

## Generated Report

After the audit completes, the tool generates a timestamped report:

```text
security_report_YYYY-MM-DD_HH-MM-SS.txt
```

Each report contains:

- Audit date and time
- Hostname
- Tool version
- Security score
- Risk level
- Security findings
- SUID/SGID file information
- Security recommendations

## Command-Line Options

| Command | Purpose |
|---|---|
| `python3 auditor.py` | Run the complete security audit |
| `python3 auditor.py --version` | Display the tool version |
| `python3 auditor.py --help` | Display usage information |

Unknown options are rejected with an error message.

## Error Handling

The tool includes error handling for common situations such as:

- Missing Linux commands
- Missing configuration files
- Permission errors
- Invalid configuration values
- Failures while retrieving system information
- Unknown command-line options

The tool reports these errors clearly instead of silently failing.

## Project Structure

```text
linux-security-auditor/
├── auditor.py
├── README.md
└── security_report_YYYY-MM-DD_HH-MM-SS.txt
```

The generated security report is created when the auditor is executed.

## Screenshots

Add screenshots showing the auditor running in the terminal and an example generated security report.

Example:

```markdown
![Linux Security Auditor Output](screenshots/auditor-output.png)

![Security Audit Report](screenshots/security-report.png)
```

## Limitations

- The tool performs selected security checks and is not a replacement for a complete security assessment.
- Security scoring is based on project-defined rules rather than a universal security standard.
- SSH results are based on explicitly configured values in the main SSH configuration file and may not represent every effective setting from included configuration files or system defaults.
- The SUID/SGID audit inventories files but does not automatically determine whether each file is malicious or unnecessary.
- Running services are listed for visibility; the tool does not automatically classify every service as vulnerable or unsafe.

## Future Improvements

- Add configurable audit policies and scoring rules.
- Add support for additional Linux distributions.
- Improve SSH effective-configuration analysis.
- Add more filesystem and system-hardening checks.
- Add structured JSON report output.
- Add optional HTML report generation.
- Add automated unit tests.
- Add CI-based testing for GitHub.

## Version

**Linux Security Auditor v1.0.0**

## Responsible Use

Use this tool only on Linux systems that you own or have explicit authorization to assess.

Review findings before making system configuration changes, especially changes involving authentication, services, permissions, or privileged files.

## Project

GitHub Repository:

https://github.com/nylagouri2003/linux-security-auditor

## License

This project is licensed under the MIT License.

See the [LICENSE](LICENSE) file for the complete license text.
