import subprocess
import os
import stat
import socket
from datetime import datetime
import sys

TOOL_VERSION = "1.0.0"

if "--version" in sys.argv:
    print(f"Linux Security Auditor v{TOOL_VERSION}")
    sys.exit(0)

if "--help" in sys.argv:
    print("Linux Security Auditor")
    print()
    print("Usage:")
    print("  python3 auditor.py")
    print("  python3 auditor.py --version")
    print("  python3 auditor.py --help")
    sys.exit(0)


for argument in sys.argv[1:]:
    if argument.startswith("--"):
        if argument not in ["--version", "--help"]:
            print(f"[ERROR] Unknown option: {argument}")
            print("Use --help for available options.")
            sys.exit(1)



security_score = 100
findings = []
recommendations = []
suid_files = []
sgid_files = []

def add_finding(level, message):
    findings.append((level, message))

def add_recommendation(message):
    recommendations.append(message)


def check_firewall():
    try:
        result = subprocess.run(
            ["sudo", "ufw", "status"],
            capture_output=True,
            text=True
        )

    except FileNotFoundError:
        print("[ERROR] UFW command not found")
        return

    if result.returncode != 0:
        print("[ERROR] Unable to check firewall status")
        return

    if "Status: active" in result.stdout:
        print("[PASS] Firewall: ACTIVE")

    else:
        global security_score
        security_score -= 20

        add_finding(
            "HIGH",
            "Firewall is inactive"
        )

        add_recommendation(
            "Enable and configure the firewall"
        )

        print("[WARNING] Firewall: INACTIVE (-20)")


def check_open_ports():
    try:
        result = subprocess.run(
            ["sudo", "ss", "-tuln"],
            capture_output=True,
            text=True
        )

    except FileNotFoundError:
        print("[ERROR] ss command not found")
        return

    if result.returncode != 0:
        print("[ERROR] Unable to retrieve open port information")
        return

    lines = result.stdout.strip().splitlines()

    if len(lines) <= 1:
        print("[PASS] Open Ports: No listening ports detected")

    else:
        global security_score
        security_score -= 10

        add_finding(
            "MEDIUM",
            "Listening ports detected"
        )

        add_recommendation(
            "Review listening ports and disable unnecessary services"
        )

        print("[WARNING] Open Ports: Listening ports detected (-10)")

        for line in lines[1:]:
            print("         " + line)


def check_users():
    try:
        result = subprocess.run(
            ["awk", "-F:", "$3 >= 1000 {print $1, $3}", "/etc/passwd"],
            capture_output=True,
            text=True
        )

    except FileNotFoundError:
        print("[ERROR] awk command not found")
        return

    if result.returncode != 0:
        print("[ERROR] Unable to retrieve user accounts")
        return

    users = []

    for line in result.stdout.strip().splitlines():
        username, uid = line.split()

        if username != "nobody":
            users.append((username, uid))

    print("[INFO] Regular Users:")

    for username, uid in users:
        print(f"       {username} (UID: {uid})")

    try:
        sudo_result = subprocess.run(
            ["getent", "group", "sudo"],
            capture_output=True,
            text=True
        )

    except FileNotFoundError:
        print("[ERROR] getent command not found")
        return

    if sudo_result.returncode != 0:
        print("[ERROR] Unable to retrieve sudo group information")
        return

    if sudo_result.stdout:
        sudo_users = sudo_result.stdout.strip().split(":")[-1]

        if sudo_users:
            print("[INFO] Sudo Users:")
            for user in sudo_users.split(","):
                print(f"       {user}")

def check_file_permissions():
    files = {
        "/etc/passwd": 0o644,
        "/etc/shadow": 0o640
    }

    print("[INFO] File Permission Audit:")

    for path, expected in files.items():
        try:
            mode = stat.S_IMODE(os.stat(path).st_mode)

            if mode == expected:
                print(f"[PASS] {path}: {oct(mode)}")
            else:
                print(
                    f"[WARNING] {path}: {oct(mode)} "
                    f"(expected {oct(expected)})"
                )

        except PermissionError:
            print(f"[ERROR] {path}: Permission denied")

        except FileNotFoundError:
            print(f"[ERROR] {path}: File not found")

        except OSError as error:
            print(f"[ERROR] {path}: Unable to check permissions ({error})")


def check_world_writable_files():
    print("[INFO] World-Writable File Audit:")

    try:
        result = subprocess.run(
            [
                "sudo",
                "find",
                "/etc",
                "/usr/local/bin",
                "-type",
                "f",
                "-perm",
                "-0002",
                "-print"
            ],
            capture_output=True,
            text=True
        )

    except FileNotFoundError:
        print("[ERROR] find command not found")
        return

    if result.returncode != 0:
        print("[ERROR] Unable to scan for world-writable files")
        return

    files = result.stdout.strip().splitlines()

    if not files:
        print("[PASS] No world-writable files detected")
        return

    global security_score
    security_score -= 10

    add_finding(
        "MEDIUM",
        f"{len(files)} world-writable file(s) detected"
    )

    add_recommendation(
        "Review world-writable files and remove unnecessary write permissions"
    )

    print(
        f"[WARNING] {len(files)} world-writable file(s) detected (-10):"
    )

    for file in files:
        print(f"       {file}")


def check_suid_sgid_files():
    print("[INFO] SUID/SGID File Audit:")

    try:
        result = subprocess.run(
            [
                "sudo",
                "find",
                "/usr",
                "/bin",
                "/sbin",
                "-type",
                "f",
                "(",
                "-perm",
                "-4000",
                "-o",
                "-perm",
                "-2000",
                ")",
                "-print"
            ],
            capture_output=True,
            text=True
        )

    except FileNotFoundError:
        print("[ERROR] find command not found")
        return

    if result.returncode != 0:
        print("[ERROR] Unable to scan for SUID/SGID files")
        return

    files = result.stdout.strip().splitlines()

    if not files:
        print("[PASS] No SUID/SGID files detected")
        return

    global suid_files, sgid_files

    suid_files = []
    sgid_files = []

    for file in files:
        try:
            mode_result = subprocess.run(
                ["stat", "-c", "%A", file],
                capture_output=True,
                text=True
            )

        except FileNotFoundError:
            print("[ERROR] stat command not found")
            return

        if mode_result.returncode != 0:
            continue

        permissions = mode_result.stdout.strip()

        if len(permissions) >= 10:
            if permissions[3] in ("s", "S"):
                suid_files.append(file)

            if permissions[6] in ("s", "S"):
                sgid_files.append(file)

    print(f"[INFO] SUID files detected: {len(suid_files)}")
    print(f"[INFO] SGID files detected: {len(sgid_files)}")

    if suid_files:
        print("[INFO] SUID Files:")

        for file in suid_files:
            print(f"       {file}")

    if sgid_files:
        print("[INFO] SGID Files:")

        for file in sgid_files:
            print(f"       {file}")



def check_ssh_config():
    config_file = "/etc/ssh/sshd_config"

    print("[INFO] SSH Configuration Audit:")

    try:
        with open(config_file, "r") as file:
            lines = file.readlines()

        settings = {}

        for line in lines:
            line = line.strip()

            # Ignore comments and blank lines
            if not line or line.startswith("#"):
                continue

            parts = line.split(None, 1)

            if len(parts) == 2:
                settings[parts[0].lower()] = parts[1].lower()

        # Root login
        if settings.get("permitrootlogin") == "yes":
            print("[WARNING] SSH: Root login is enabled")
        else:
            print("[PASS] SSH: Root login is not explicitly enabled")

        # Password authentication
        if settings.get("passwordauthentication") == "yes":
            print("[WARNING] SSH: Password authentication is enabled")
        else:
            print("[INFO] SSH: Password authentication is not explicitly enabled")

        # Public key authentication
        if settings.get("pubkeyauthentication") == "yes":
            print("[PASS] SSH: Public key authentication is enabled")
        else:
            print("[INFO] SSH: Public key authentication is not explicitly enabled")

        # X11 forwarding
        if settings.get("x11forwarding") == "yes":
            print("[INFO] SSH: X11 forwarding is enabled")
        else:
            print("[PASS] SSH: X11 forwarding is disabled")

    except FileNotFoundError:
        print("[ERROR] SSH configuration file not found")

    except PermissionError:
        print("[ERROR] Permission denied reading SSH configuration")

    except OSError as error:
        print(f"[ERROR] Unable to read SSH configuration ({error})")

def check_running_services():
    try:
        result = subprocess.run(
            [
                "systemctl",
                "--type=service",
                "--state=running",
                "--no-pager",
                "--no-legend"
            ],
            capture_output=True,
            text=True
        )

    except FileNotFoundError:
        print("[ERROR] systemctl command not found")
        return

    print("[INFO] Running Services:")

    if result.returncode != 0:
        print("[ERROR] Unable to retrieve running services")
        return

    services = []

    for line in result.stdout.strip().splitlines():
        parts = line.split(None, 4)

        if parts:
            service = parts[0]
            services.append(service)

    if not services:
        print("       No running services detected")
        return

    for service in services:
        print(f"       {service}")

    print(f"[INFO] Total Running Services: {len(services)}")


def check_package_updates():
    try:
        result = subprocess.run(
            ["apt", "list", "--upgradable"],
            capture_output=True,
            text=True
        )

    except FileNotFoundError:
        print("[ERROR] apt command not found")
        return

    print("[INFO] Package Update Audit:")

    if result.returncode != 0:
        print("[ERROR] Unable to check package updates")
        return

    lines = [
        line for line in result.stdout.strip().splitlines()
        if line and not line.startswith("Listing...")
    ]

    if not lines:
        print("[PASS] System packages are up to date")
        return

    global security_score
    security_score -= 5

    add_finding(
        "LOW",
        f"{len(lines)} package(s) have available updates"
    )

    add_recommendation(
        "Install available system package updates"
    )

    print(
        f"[WARNING] {len(lines)} package(s) have available updates (-5):"
    )

    for package in lines:
        package_name = package.split("/")[0]
        print(f"       {package_name}")


def check_password_policy():
    config_file = "/etc/login.defs"

    print("[INFO] Password Policy Audit:")

    try:
        settings = {}

        with open(config_file, "r") as file:
            for line in file:
                line = line.strip()

                if not line or line.startswith("#"):
                    continue

                parts = line.split()

                if len(parts) >= 2:
                    settings[parts[0]] = parts[1]

        max_days = int(settings.get("PASS_MAX_DAYS", 99999))
        min_days = int(settings.get("PASS_MIN_DAYS", 0))
        warn_days = int(settings.get("PASS_WARN_AGE", 0))

        if max_days >= 365:
            global security_score
            security_score -= 10

            add_finding(
                "HIGH",
                f"Maximum password age is {max_days} days"
            )

            add_recommendation(
                "Configure an appropriate maximum password age"
            )

            print(
                f"[WARNING] Maximum password age: {max_days} days (-10)"
            )
        else:
            print(
                f"[PASS] Maximum password age: {max_days} days"
            )

        if min_days == 0:
            print("[INFO] Minimum password age: 0 days")
        else:
            print(
                f"[PASS] Minimum password age: {min_days} days"
            )

        if warn_days >= 7:
            print(
                f"[PASS] Password expiration warning: {warn_days} days"
            )
        else:
            print(
                f"[INFO] Password expiration warning: {warn_days} days"
            )

    except FileNotFoundError:
        print("[ERROR] Password policy file not found")

    except PermissionError:
        print("[ERROR] Permission denied reading password policy")

    except ValueError:
        print("[ERROR] Invalid password policy value")

    except OSError as error:
        print(f"[ERROR] Unable to read password policy ({error})")


def show_security_score():
    print("\n================================")
    print(f"SECURITY SCORE: {security_score}/100")

    if security_score >= 90:
        print("RISK LEVEL: LOW")
    elif security_score >= 70:
        print("RISK LEVEL: MEDIUM")
    elif security_score >= 50:
        print("RISK LEVEL: HIGH")
    else:
        print("RISK LEVEL: CRITICAL")


def generate_report():
    high_count = sum(1 for level, message in findings if level == "HIGH")
    medium_count = sum(1 for level, message in findings if level == "MEDIUM")
    low_count = sum(1 for level, message in findings if level == "LOW")

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_file = f"security_report_{timestamp}.txt"


    with open(report_file, "w") as report:
        report.write("================================\n")
        report.write("LINUX SECURITY AUDIT REPORT\n")
        report.write("================================\n\n")


        report.write(
            f"Audit Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        )

        report.write(f"Hostname: {socket.gethostname()}\n")
        report.write(f"Tool Version: {TOOL_VERSION}\n\n")

        report.write(f"Security Score: {security_score}/100\n")

        if security_score >= 90:
            risk_level = "LOW"
        elif security_score >= 70:
            risk_level = "MEDIUM"
        elif security_score >= 50:
            risk_level = "HIGH"
        else:
            risk_level = "CRITICAL"

        report.write(f"Risk Level: {risk_level}\n\n")

        report.write("AUDIT SUMMARY\n")
        report.write("--------------------------------\n")
        report.write(f"Total Findings: {len(findings)}\n")
        report.write(f"High Risk Findings: {high_count}\n")
        report.write(f"Medium Risk Findings: {medium_count}\n")
        report.write(f"Low Risk Findings: {low_count}\n\n")

        report.write("SECURITY FINDINGS\n")
        report.write("--------------------------------\n")

        report.write("SUID/SGID FILES\n")
        report.write("--------------------------------\n")

        report.write(f"SUID Files: {len(suid_files)}\n")
        report.write(f"SGID Files: {len(sgid_files)}\n\n")

        if suid_files:
            report.write("SUID Files:\n")
            for file in suid_files:
                report.write(f"- {file}\n")

        if sgid_files:
            report.write("\nSGID Files:\n")
            for file in sgid_files:
                report.write(f"- {file}\n")

        report.write("\n")


        if findings:
            for level, message in findings:
                report.write(f"[{level}] {message}\n")
        else:
            report.write("[PASS] No security findings detected\n")

        report.write("\nSECURITY RECOMMENDATIONS\n")
        report.write("--------------------------------\n")

        if recommendations:
            for recommendation in recommendations:
                report.write(f"- {recommendation}\n")
        else:
            report.write("[PASS] No recommendations at this time\n")

        report.write("\n================================\n")

    print(f"\n[INFO] Security report generated: {report_file}")



print("================================")
print("     LINUX SECURITY AUDITOR")
print("================================")

check_firewall()
check_open_ports()
check_users()
check_file_permissions()
check_world_writable_files()
check_suid_sgid_files()
check_ssh_config()
check_running_services()
check_package_updates()
check_password_policy()


show_security_score()
generate_report()
