"""
SupaGuard Cross-Platform System & Persistence Hunter
Audits macOS, Linux, and Windows for stealth persistence artifacts, rogue background daemons, and shell hijacks.
"""

import os
import sys
import re
import subprocess
import shutil
import signal
from pathlib import Path

IS_MAC = sys.platform == "darwin"
IS_LINUX = sys.platform.startswith("linux")
IS_WIN = sys.platform == "win32"

# ----------------- macOS Auditor -----------------
def audit_macos():
    findings = []
    import plistlib
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

# ----------------- Linux Auditor -----------------
def audit_linux():
    findings = []
    
    # 1. Check /etc/ld.so.preload (Rootkit Persistence)
    preload_file = Path("/etc/ld.so.preload")
    if preload_file.exists():
        try:
            content = preload_file.read_text(errors="ignore").strip()
            if content:
                findings.append({
                    "severity": "CRITICAL",
                    "category": "Linux LD_PRELOAD Hook",
                    "file": str(preload_file),
                    "detail": f"ld.so.preload contains active library injection: {content[:100]}"
                })
        except Exception:
            pass

    # 2. Check Systemd Units
    systemd_paths = [
        Path.home() / ".config" / "systemd" / "user",
        Path("/etc/systemd/system")
    ]
    for sp in systemd_paths:
        if not sp.exists():
            continue
        for s_file in sp.glob("*.service"):
            try:
                text = s_file.read_text(errors="ignore")
                for line in text.splitlines():
                    if line.startswith("ExecStart=") and re.search(r"(?:/tmp/|/dev/shm/|curl|wget|python\s+-c|bash\s+-i|nc\s+)", line, re.IGNORECASE):
                        findings.append({
                            "severity": "CRITICAL",
                            "category": "Suspicious Systemd Service",
                            "file": str(s_file),
                            "detail": f"Service executes suspicious payload: {line[:100]}"
                        })
            except Exception:
                pass

    # 3. Check /etc/cron.* and crontabs
    cron_dirs = [Path("/etc/cron.d"), Path("/etc/cron.daily"), Path("/etc/cron.hourly"), Path("/var/spool/cron/crontabs")]
    for cd in cron_dirs:
        if not cd.exists():
            continue
        for cf in cd.iterdir():
            if cf.is_file():
                try:
                    text = cf.read_text(errors="ignore")
                    for line in text.splitlines():
                        if not line.startswith("#") and re.search(r"(?:/tmp/|/dev/shm/|curl|wget|nc\s+|base64)", line, re.IGNORECASE):
                            findings.append({
                                "severity": "HIGH",
                                "category": "Suspicious Linux Cron Entry",
                                "file": str(cf),
                                "detail": f"Cron job executes suspicious script: {line[:100]}"
                            })
                except Exception:
                    pass
    return findings

# ----------------- Windows Auditor -----------------
def audit_windows():
    findings = []
    
    # 1. Check Startup folder
    appdata = os.environ.get("APPDATA")
    if appdata:
        startup_dir = Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
        if startup_dir.exists():
            for item in startup_dir.iterdir():
                if item.suffix.lower() in [".bat", ".cmd", ".vbs", ".ps1", ".exe"]:
                    findings.append({
                        "severity": "HIGH",
                        "category": "Windows Startup Item",
                        "file": str(item),
                        "detail": f"Executable file in Startup folder: {item.name}"
                    })

    # 2. Check Registry Run Keys via 'reg query'
    reg_keys = [
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
    ]
    for rk in reg_keys:
        try:
            proc = subprocess.run(["reg", "query", rk], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if proc.returncode == 0:
                for line in proc.stdout.splitlines():
                    line = line.strip()
                    if re.search(r"(?:powershell.*-enc|cmd\.exe\s+/c|wscript\.exe|temp\\|appdata\\local\\temp)", line, re.IGNORECASE):
                        findings.append({
                            "severity": "CRITICAL",
                            "category": "Suspicious Registry Run Key",
                            "file": rk,
                            "detail": f"Run entry executes suspicious payload: {line[:100]}"
                        })
        except Exception:
            pass

    # 3. Check PowerShell Profile
    userprofile = os.environ.get("USERPROFILE")
    if userprofile:
        ps_profiles = [
            Path(userprofile) / "Documents" / "WindowsPowerShell" / "profile.ps1",
            Path(userprofile) / "Documents" / "PowerShell" / "profile.ps1"
        ]
        for psp in ps_profiles:
            if psp.exists():
                try:
                    txt = psp.read_text(errors="ignore")
                    if re.search(r"(?:DownloadString|IEX|Invoke-Expression|FromBase64String)", txt, re.IGNORECASE):
                        findings.append({
                            "severity": "CRITICAL",
                            "category": "Malicious PowerShell Profile",
                            "file": str(psp),
                            "detail": f"PowerShell profile contains download cradle / encoded execution: {txt[:100]}"
                        })
                except Exception:
                    pass

    return findings

# ----------------- Cross-Platform Shell Profiles -----------------
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
    if IS_WIN:
        return findings
    try:
        proc = subprocess.run(["crontab", "-l"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if proc.returncode == 0 and proc.stdout:
            for line in proc.stdout.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    if re.search(r"(?:/tmp/|/dev/shm/|curl|wget|nc\s+|base64|sh\s+-c)", line, re.IGNORECASE):
                        findings.append({
                            "severity": "HIGH",
                            "category": "Suspicious User Crontab",
                            "file": "crontab",
                            "detail": f"Active cron job executes suspicious script: {line[:100]}"
                        })
    except Exception:
        pass
    return findings


# ----------------- Node.js & Package Manager Auditor -----------------
def audit_node_installations(fix=False):
    findings = []
    
    # 1. Check for rogue ~/.node_modules directory in home
    rogue_dir = Path.home() / ".node_modules"
    if rogue_dir.is_dir():
        is_malicious = False
        sample_files = list(rogue_dir.glob(".npm-ws*"))
        if sample_files or (rogue_dir / ".npm-ws-runner.js").exists() or (rogue_dir / ".npm-ws.json").exists():
            is_malicious = True
        
        detail = f"Rogue ~/.node_modules malware staging directory found ({len(sample_files)} .npm-ws artifacts)."
        if fix and is_malicious:
            try:
                shutil.rmtree(str(rogue_dir))
                detail += " -> [REMEDIATED: DELETED]"
            except Exception as e:
                detail += f" -> [DELETE FAILED: {e}]"

        findings.append({
            "severity": "CRITICAL",
            "category": "Rogue ~/.node_modules Malware Runner Staging",
            "file": str(rogue_dir),
            "detail": detail
        })
    elif rogue_dir.is_file() and rogue_dir.stat().st_size == 0:
        # Immutable OS-level immunization lock preventing malware directory recreation
        pass

    # 2. Check npm/lib/cli.js files across system and nvm installations
    cli_candidates = []
    nvm_dir = Path.home() / ".nvm" / "versions" / "node"
    if nvm_dir.exists():
        for ver in nvm_dir.iterdir():
            candidate = ver / "lib" / "node_modules" / "npm" / "lib" / "cli.js"
            if candidate.exists():
                cli_candidates.append(candidate)

    system_paths = [
        Path("/usr/local/lib/node_modules/npm/lib/cli.js"),
        Path("/opt/homebrew/lib/node_modules/npm/lib/cli.js"),
        Path("/opt/local/lib/node_modules/npm/lib/cli.js"),
        Path.home() / ".fnm" / "current" / "lib" / "node_modules" / "npm" / "lib" / "cli.js"
    ]
    for sp in system_paths:
        if sp.exists() and sp not in cli_candidates:
            cli_candidates.append(sp)

    try:
        which_npm = subprocess.run(["which", "npm"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if which_npm.returncode == 0 and which_npm.stdout.strip():
            npm_bin = Path(which_npm.stdout.strip()).resolve()
            candidate = npm_bin.parent.parent / "lib" / "node_modules" / "npm" / "lib" / "cli.js"
            if candidate.exists() and candidate not in cli_candidates:
                cli_candidates.append(candidate)
    except Exception:
        pass

    for cli_file in cli_candidates:
        try:
            txt = cli_file.read_text(encoding="utf-8", errors="ignore")
            injected = False
            matched_pattern = ""
            if re.search(r"/\*M[0-9A-Za-z]+\*/|cp\.spawn\(process\.execPath|npm-ws-runner", txt):
                injected = True
                matched_pattern = "/*M[0-9A-Z]+*/ or detached payload runner"

            if injected:
                detail = f"Backdoor hook injected into npm CLI ({matched_pattern})."
                if fix:
                    try:
                        clean_lines = [line for line in txt.splitlines() if not re.search(r"/\*M[0-9A-Za-z]+\*/|npm-ws-runner", line)]
                        cleaned_txt = "\n".join(clean_lines) + "\n"
                        cli_file.write_text(cleaned_txt, encoding="utf-8")
                        detail += " -> [REMEDIATED: DISINFECTED & CLEANED]"
                    except Exception as e:
                        detail += f" -> [DISINFECTION FAILED: {e}]"

                findings.append({
                    "severity": "CRITICAL",
                    "category": "Node / npm CLI Entrypoint Backdoor Injection",
                    "file": str(cli_file),
                    "detail": detail
                })
        except Exception:
            pass

    return findings

def audit_ide_injections(fix=False):
    findings = []
    
    targets = []
    if IS_MAC:
        targets.extend([
            Path('/Applications/Visual Studio Code.app/Contents/Resources/app/out/main.js'),
            Path('/Applications/Cursor.app/Contents/Resources/app/out/main.js'),
            Path('/Applications/Antigravity.app/Contents/Resources/app/out/main.js'),
            Path('/Applications/GitHub Desktop.app/Contents/Resources/app/main.js')
        ])
        discord_dir = Path.home() / 'Library' / 'Application Support' / 'discord'
        if discord_dir.exists():
            for p in discord_dir.glob('**/discord_desktop_core/index.js'):
                targets.append(p)
    elif IS_LINUX:
        targets.extend([
            Path('/usr/share/code/resources/app/out/main.js'),
            Path('/usr/share/cursor/resources/app/out/main.js'),
            Path('/usr/share/antigravity/resources/app/out/main.js')
        ])
    elif IS_WIN:
        local_appdata = os.environ.get('LOCALAPPDATA', '')
        if local_appdata:
            targets.extend([
                Path(local_appdata) / 'Programs' / 'Microsoft VS Code' / 'resources' / 'app' / 'out' / 'main.js',
                Path(local_appdata) / 'Programs' / 'cursor' / 'resources' / 'app' / 'out' / 'main.js'
            ])

    for target in targets:
        if not target.exists():
            continue
        try:
            content = target.read_text(errors='ignore')
            inz_marker = any(m in content for m in ['__inzCR', '__inzRQ', 'main.inz.cjs', '/*M260630A*/', '/*C250', '/*C260'])
            parent = target.parent
            rogue_cjs = parent / 'main.inz.cjs'
            backup_orig = parent / (target.name + '.inz.orig')
            
            if inz_marker or rogue_cjs.exists():
                detail = f'Rogue Electron/IDE injection detected in {target.name}.'
                if fix:
                    if backup_orig.exists():
                        shutil.copy2(str(backup_orig), str(target))
                        backup_orig.unlink(missing_ok=True)
                        rogue_cjs.unlink(missing_ok=True)
                        target.chmod(0o444)
                        detail += ' -> [REMEDIATED: RESTORED FROM CLEAN BACKUP & LOCKED READ-ONLY]'
                    else:
                        # Strip injection markers
                        clean_content = re.sub(r'import\s*\{[^}]*__inzCR[^;]*;\s*', '', content)
                        clean_content = re.sub(r'/\*[MC]2[0-9]{5}[A-Z]\*/', '', clean_content)
                        target.write_text(clean_content)
                        rogue_cjs.unlink(missing_ok=True)
                        target.chmod(0o444)
                        detail += ' -> [REMEDIATED: INJECTION STRIPPED & LOCKED READ-ONLY]'
                
                findings.append({
                    'severity': 'CRITICAL',
                    'category': 'Electron Desktop IDE Injected Loader',
                    'file': str(target),
                    'detail': detail
                })
        except Exception as e:
            pass
            
    return findings

def audit_running_processes(fix=False):
    findings = []
    if IS_WIN:
        return findings
    try:
        proc = subprocess.run(["ps", "-eo", "pid,command"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if proc.returncode == 0 and proc.stdout:
            for line in proc.stdout.splitlines()[1:]:
                parts = line.strip().split(None, 1)
                if len(parts) < 2:
                    continue
                pid_str, cmd = parts[0], parts[1]
                if re.search(r"npm-ws|\.npm-ws-runner|KEY.*?eval|95\.135\.181\.151", cmd, re.IGNORECASE):
                    detail = f"Suspicious active process (PID {pid_str}): {cmd[:100]}"
                    if fix:
                        try:
                            os.kill(int(pid_str), signal.SIGKILL)
                            detail += " -> [REMEDIATED: KILLED]"
                        except Exception as e:
                            detail += f" -> [KILL FAILED: {e}]"

                    findings.append({
                        "severity": "CRITICAL",
                        "category": "Active Malicious Node / Backdoor Process",
                        "file": f"PID:{pid_str}",
                        "detail": detail
                    })
    except Exception:
        pass
    return findings

def run_system_audit(fix=False):
    os_name = "macOS" if IS_MAC else ("Linux" if IS_LINUX else "Windows")
    print(f"\n\033[1;96m==> SupaGuard System & Persistence Hunter ({os_name})\033[0m\n")
    
    all_findings = []
    
    print(" • Inspecting Node.js runtimes, npm CLI entrypoints & Home directory...")
    all_findings.extend(audit_node_installations(fix=fix))
    print(" • Auditing Electron desktop IDE entrypoints (VS Code, Cursor, Antigravity, Discord)...")
    all_findings.extend(audit_ide_injections(fix=fix))
    print(" • Auditing running processes for background stealers & unauthorized node payloads...")
    all_findings.extend(audit_running_processes(fix=fix))
    if IS_MAC:
        print(" • Inspecting macOS LaunchDaemons & LaunchAgents...")
        all_findings.extend(audit_macos())
    elif IS_LINUX:
        print(" • Inspecting Linux Systemd Units, Crontabs & ld.so.preload...")
        all_findings.extend(audit_linux())
    elif IS_WIN:
        print(" • Inspecting Windows Registry Run Keys, Startup & PowerShell Profiles...")
        all_findings.extend(audit_windows())

    if not IS_WIN:
        print(" • Inspecting Shell Startup Profiles (.zshrc, .bashrc)...")
        all_findings.extend(audit_shell_profiles())
        print(" • Inspecting User Crontabs...")
        all_findings.extend(audit_crontabs())

    print("\n" + "=" * 75)
    print(f"\033[1mSUPAGUARD {os_name.upper()} SYSTEM SECURITY AUDIT REPORT\033[0m")
    print("=" * 75)

    if not all_findings:
        print(f"\n\033[1;42;97m SYSTEM SECURE \033[0m \033[92mNo rogue persistence hooks or suspicious startup scripts detected on {os_name}.\033[0m\n")
        return

    print(f"\nDiscovered \033[1;91m{len(all_findings)}\033[0m security issues / persistence artifacts:\n")
    for idx, item in enumerate(all_findings, 1):
        sev_color = "\033[1;41;97m" if item["severity"] == "CRITICAL" else "\033[1;91m"
        print(f"[{idx}] {sev_color} {item['severity']} \033[0m \033[1m{item['category']}\033[0m")
        print(f"     Location: {item['file']}")
        print(f"     Detail:   {item['detail']}")
        print()
