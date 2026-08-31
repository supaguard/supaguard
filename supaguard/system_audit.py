"""
SupaGuard System & Persistence Hunter
Audits LaunchDaemons, LaunchAgents, shell startup profiles (.zshrc, .bashrc), and scheduled crontabs.
"""

import os
import re
import plistlib
import subprocess
from pathlib import Path

def audit_launch_agents():
    findings = []
    scan_paths = [
        Path.home() / "Library" / "LaunchAgents",
        Path("/Library/LaunchAgents"),
        Path("/Library/LaunchDaemons")
    ]

    for base in scan_paths:
        if not base.exists():
            continue
        for plist_file in base.glob("*.plist"):
            try:
                with open(plist_file, "rb") as f:
                    data = plistlib.load(f)
                    prog = data.get("Program", "")
                    prog_args = data.get("ProgramArguments", [])
                    prog_str = f"{prog} {' '.join(str(x) for x in prog_args)}"
                    
                    if re.search(r"(?:/tmp/|/var/tmp/|/private/tmp/|\.cache/|\.hidden|curl\s|wget\s|python\s+-c|bash\s+-i|nc\s+)", prog_str, re.IGNORECASE):
                        findings.append({
                            "severity": "CRITICAL",
                            "category": "Suspicious LaunchAgent / Daemon",
                            "file": str(plist_file),
                            "detail": f"Plist executes suspicious command: {prog_str[:120]}"
                        })
            except Exception:
                pass
    return findings

def audit_shell_profiles():
    findings = []
    profile_files = [
        Path.home() / ".zshrc",
        Path.home() / ".bashrc",
        Path.home() / ".zprofile",
        Path.home() / ".bash_profile",
        Path.home() / ".profile",
        Path.home() / ".zsh_aliases"
    ]

    sensitive_commands = ["sudo", "git", "ssh", "scp", "curl", "brew", "node", "npm"]

    for pf in profile_files:
        if not pf.exists():
            continue
        try:
            content = pf.read_text(encoding="utf-8", errors="ignore")
            lines = content.splitlines()
            for line_no, line in enumerate(lines, 1):
                clean_line = line.strip()
                if clean_line.startswith("#"):
                    continue

                for cmd in sensitive_commands:
                    if re.search(rf"""^alias\s+{cmd}\s*=""", clean_line):
                        findings.append({
                            "severity": "HIGH",
                            "category": "Shell Alias Override",
                            "file": f"{pf}:{line_no}",
                            "detail": f"Sensitive command '{cmd}' is overridden by an alias: {clean_line[:100]}"
                        })

                if re.search(r"""(?:eval\s*\(?base64|curl\s+[^|]+\|\s*(?:sh|bash)|/dev/tcp/)""", clean_line, re.IGNORECASE):
                    findings.append({
                        "severity": "CRITICAL",
                        "category": "Suspicious Shell Startup Command",
                        "file": f"{pf}:{line_no}",
                        "detail": f"Suspicious remote execution/base64 in startup script: {clean_line[:100]}"
                    })
        except Exception:
            pass
    return findings

def audit_crontabs():
    findings = []
    try:
        proc = subprocess.run(["crontab", "-l"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if proc.returncode == 0 and proc.stdout:
            for line in proc.stdout.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    if re.search(r"(?:/tmp/|curl|wget|nc\s+|base64|sh\s+-c)", line, re.IGNORECASE):
                        findings.append({
                            "severity": "HIGH",
                            "category": "Suspicious User Crontab",
                            "file": "crontab",
                            "detail": f"Active cron job executes suspicious script: {line[:100]}"
                        })
    except Exception:
        pass
    return findings

def run_system_audit():
    print("\n\033[1;96m==> SupaGuard System & Persistence Hunter (macOS)\033[0m\n")
    print(" • Inspecting LaunchDaemons & LaunchAgents...")
    agent_findings = audit_launch_agents()
    print(" • Inspecting Shell Startup Profiles (.zshrc, .bashrc)...")
    profile_findings = audit_shell_profiles()
    print(" • Inspecting User Crontabs...")
    cron_findings = audit_crontabs()

    all_findings = agent_findings + profile_findings + cron_findings

    print("\n" + "=" * 75)
    print("\033[1mSUPAGUARD SYSTEM SECURITY AUDIT REPORT\033[0m")
    print("=" * 75)

    if not all_findings:
        print("\n\033[1;42;97m SYSTEM SECURE \033[0m \033[92mNo rogue LaunchAgents, stealth shell aliases, or persistence backdoors detected.\033[0m\n")
        return

    print(f"\nDiscovered \033[1;91m{len(all_findings)}\033[0m security issues / persistence artifacts:\n")
    for idx, item in enumerate(all_findings, 1):
        sev_color = "\033[1;41;97m" if item["severity"] == "CRITICAL" else "\033[1;91m"
        print(f"[{idx}] {sev_color} {item['severity']} \033[0m \033[1m{item['category']}\033[0m")
        print(f"     Location: {item['file']}")
        print(f"     Detail:   {item['detail']}")
        print()
