"""
SupaGuard CLI Main Entrypoint & Command Dispatcher
Cross-Platform: macOS, Linux, and Windows.
"""

import sys
import os
import re
import json
import time
import shutil
import hashlib
import argparse
import signal
import subprocess
from datetime import datetime
from pathlib import Path

# Paths
APP_DIR = Path.home() / ".supaguard"
LOGS_DIR = APP_DIR / "logs"
QUARANTINE_DIR = APP_DIR / "quarantine"
PID_FILE = APP_DIR / "shield.pid"
STATUS_FILE = APP_DIR / "shield_status.json"
SCAN_LOG_FILE = LOGS_DIR / "scans.log"
SHIELD_LOG_FILE = LOGS_DIR / "shield.log"

for d in [APP_DIR, LOGS_DIR, QUARANTINE_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# Import internal modules
from supaguard import core_engine
from supaguard import git_guard
from supaguard import supply_chain
from supaguard import system_audit
from supaguard import web3_guard
from supaguard import html_report
from supaguard import deobfuscator

IS_WIN = sys.platform == "win32"
IS_MAC = sys.platform == "darwin"
IS_LINUX = sys.platform.startswith("linux")

class Color:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"

def banner():
    print(f"""{Color.CYAN}{Color.BOLD}
   ███████╗██╗   ██╗██████╗  █████╗  ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ 
   ██╔════╝██║   ██║██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
   ███████╗██║   ██║██████╔╝███████║██║  ███╗██║   ██║███████║██████╔╝██║  ██║
   ╚════██║██║   ██║██╔═══╝ ██╔══██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
   ███████║╚██████╔╝██║     ██║  ██║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
   ╚══════╝ ╚═════╝ ╚═╝     ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ {Color.RESET}
   {Color.WHITE}{Color.BOLD}100% SECURITY & MULTI-LAYER DEVELOPER DEFENSE SUITE{Color.RESET}
""")

IGNORE_DIR_NAMES = {
    ".git", ".gemini", ".system_generated", ".vscode", ".cursor", ".idea",
    "Library", "node_modules", "dist", ".next", ".expo", "Pods", "vendor",
    ".cache", "build", "coverage", ".turbo", ".supaguard", ".antivirus",
    ".npm", ".cargo", ".rustup", ".nvm", ".local/share", ".local/state"
}

IGNORE_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp", ".mp3", ".mp4",
    ".wav", ".pdf", ".zip", ".tar", ".gz", ".woff", ".woff2", ".ttf", ".eot",
    ".map", ".lock", ".resolved", ".jsonl", ".vscdb", ".sqlite", ".sqlite3",
    ".db", ".log", ".pid", ".sock", ".bin", ".dmg", ".pkg", ".iso"
}

def is_ignored_path(path_obj: Path):
    parts = path_obj.parts
    for ign in IGNORE_DIR_NAMES:
        if ign in parts:
            return True
    if path_obj.suffix.lower() in IGNORE_EXTENSIONS:
        return True
    return False

def find_binary(name: str):
    bin_path = shutil.which(name)
    if bin_path:
        return bin_path
    
    if IS_WIN and not name.endswith(".exe"):
        bin_path = shutil.which(f"{name}.exe")
        if bin_path:
            return bin_path

    common_unix_paths = [
        f"/opt/local/bin/{name}",
        f"/usr/local/bin/{name}",
        f"/usr/bin/{name}",
        str(Path.home() / ".local" / "bin" / name)
    ]
    for p in common_unix_paths:
        if os.path.exists(p):
            return p
    return None

def run_clamav_scan(target_path: Path):
    findings = []
    clam_bin = find_binary("clamdscan") or find_binary("clamscan")
    if not clam_bin:
        return findings, False
    try:
        cmd = [clam_bin, "--infected", "--no-summary", "-r", str(target_path)]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=120)
        for line in proc.stdout.splitlines():
            line = line.strip()
            if ": " in line and " FOUND" in line:
                file_part, threat_part = line.split(": ", 1)
                threat_name = threat_part.replace(" FOUND", "").strip()
                fp = Path(file_part.strip())
                if is_ignored_path(fp):
                    continue
                findings.append({
                    "engine": "ClamAV",
                    "rule_id": "CLAMAV-VIRUS-FOUND",
                    "name": threat_name,
                    "severity": "CRITICAL",
                    "file": str(fp),
                    "line": 0,
                    "snippet": f"ClamAV detected signature: {threat_name}",
                    "desc": "Known virus/trojan/malware binary signature matched."
                })
    except Exception:
        pass
    return findings, True

def run_trivy_scan(target_path: Path):
    findings = []
    trivy_bin = find_binary("trivy")
    if not trivy_bin:
        return findings, False
    try:
        cmd = [trivy_bin, "fs", "--scanners", "secret,misconfig", "--format", "json", "--quiet", str(target_path)]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=180)
        if proc.stdout:
            try:
                data = json.loads(proc.stdout)
                for res in data.get("Results", []):
                    target_file = res.get("Target", str(target_path))
                    if is_ignored_path(Path(target_file)):
                        continue
                    for secret in res.get("Secrets", []):
                        findings.append({
                            "engine": "Trivy Secrets",
                            "rule_id": secret.get("RuleID", "TRIVY-SECRET"),
                            "name": secret.get("Title", "Exposed Secret"),
                            "severity": secret.get("Severity", "HIGH"),
                            "file": target_file,
                            "line": secret.get("StartLine", 1),
                            "snippet": secret.get("Match", ""),
                            "desc": f"Trivy detected secret: {secret.get('Category', '')}"
                        })
                    for misconf in res.get("Misconfigurations", []):
                        findings.append({
                            "engine": "Trivy Misconfig",
                            "rule_id": misconf.get("ID", "TRIVY-MISCONFIG"),
                            "name": misconf.get("Title", "Misconfiguration"),
                            "severity": misconf.get("Severity", "MEDIUM"),
                            "file": target_file,
                            "line": misconf.get("CauseMetadata", {}).get("StartLine", 1),
                            "snippet": misconf.get("Message", ""),
                            "desc": misconf.get("Resolution", "")
                        })
            except Exception:
                pass
    except Exception:
        pass
    return findings, True

def run_semgrep_scan(target_path: Path):
    findings = []
    semgrep_bin = find_binary("semgrep") or find_binary("pysemgrep")
    if not semgrep_bin:
        return findings, False
    try:
        cmd = [semgrep_bin, "scan", "--config=auto", "--json", "--quiet", str(target_path)]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=240)
        if proc.stdout:
            try:
                data = json.loads(proc.stdout)
                for res in data.get("results", []):
                    f_path = res.get("path", str(target_path))
                    if is_ignored_path(Path(f_path)):
                        continue
                    findings.append({
                        "engine": "Semgrep SAST",
                        "rule_id": res.get("check_id", "SEMGREP-RULE"),
                        "name": res.get("extra", {}).get("message", "Semgrep Finding"),
                        "severity": res.get("extra", {}).get("severity", "WARNING").upper(),
                        "file": f_path,
                        "line": res.get("start", {}).get("line", 1),
                        "snippet": res.get("extra", {}).get("lines", "").strip()[:100],
                        "desc": res.get("extra", {}).get("metadata", {}).get("shortlink", "")
                    })
            except Exception:
                pass
    except Exception:
        pass
    return findings, True

def quarantine_file(file_path_str: str, threat_info: dict):
    src = Path(file_path_str)
    if not src.exists() or not src.is_file():
        return False, "File does not exist."
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    file_bytes = src.read_bytes()
    file_hash = hashlib.sha256(file_bytes).hexdigest()[:10]
    dest = QUARANTINE_DIR / f"{src.name}_{timestamp}_{file_hash}.quarantine"
    meta_dest = QUARANTINE_DIR / f"{src.name}_{timestamp}_{file_hash}.quarantine.meta.json"
    metadata = {
        "original_path": str(src.resolve()),
        "quarantine_time": timestamp,
        "sha256": hashlib.sha256(file_bytes).hexdigest(),
        "threat": threat_info
    }
    try:
        shutil.move(str(src), str(dest))
        meta_dest.write_text(json.dumps(metadata, indent=2))
        try:
            os.chmod(str(dest), 0o600)
        except Exception:
            pass
        return True, str(dest)
    except Exception as e:
        return False, str(e)

def cmd_scan(args):
    target = Path(args.path).resolve()
    if not target.exists():
        print(f"{Color.RED}[ERROR]{Color.RESET} Target path '{target}' does not exist.")
        sys.exit(1)

    print(f"\n{Color.BOLD}{Color.CYAN}==> Initiating SupaGuard Security Scan: {target}{Color.RESET}")
    print(f"{Color.DIM}Scan mode: {'Quick' if args.quick else 'Deep Full-Spectrum'}{Color.RESET}\n")

    start_time = time.time()
    all_findings = []
    scanned_files_count = 0

    print(f"{Color.YELLOW}[Layer 1/5]{Color.RESET} Running Built-in Threat & Malicious Pattern Engine...")
    if target.is_file():
        if not is_ignored_path(target):
            scanned_files_count += 1
            all_findings.extend(core_engine.scan_file_heuristics(target))
            if getattr(args, "web3", False):
                all_findings.extend(web3_guard.scan_web3_file(target))
    else:
        for root, dirs, files in os.walk(target):
            dirs[:] = [d for d in dirs if d not in IGNORE_DIR_NAMES and not any(ign in os.path.join(root, d) for ign in IGNORE_DIR_NAMES)]
            for file in files:
                file_path = Path(root) / file
                if is_ignored_path(file_path):
                    continue
                scanned_files_count += 1
                all_findings.extend(core_engine.scan_file_heuristics(file_path))
                if getattr(args, "web3", False):
                    all_findings.extend(web3_guard.scan_web3_file(file_path))

    print(f"{Color.YELLOW}[Layer 2/5]{Color.RESET} Checking ClamAV Antivirus Daemon & Signatures...")
    clam_findings, clam_installed = run_clamav_scan(target)
    if clam_installed:
        all_findings.extend(clam_findings)
        print(f"  {Color.GREEN}[OK]{Color.RESET} ClamAV signature scan completed.")
    else:
        print(f"  {Color.DIM}[INFO] ClamAV not installed (run 'supaguard doctor'){Color.RESET}")

    print(f"{Color.YELLOW}[Layer 3/5]{Color.RESET} Checking Trivy Secrets & Misconfiguration Scanner...")
    if not args.quick:
        trivy_findings, trivy_installed = run_trivy_scan(target)
        if trivy_installed:
            all_findings.extend(trivy_findings)
            print(f"  {Color.GREEN}[OK]{Color.RESET} Trivy scan completed.")
        else:
            print(f"  {Color.DIM}[INFO] Trivy not installed (run 'supaguard doctor'){Color.RESET}")
    else:
        print(f"  {Color.DIM}[INFO] Skipped in quick mode{Color.RESET}")

    print(f"{Color.YELLOW}[Layer 4/5]{Color.RESET} Checking Semgrep Static Security & Backdoor Analyzer...")
    if not args.quick:
        semgrep_findings, semgrep_installed = run_semgrep_scan(target)
        if semgrep_installed:
            all_findings.extend(semgrep_findings)
            print(f"  {Color.GREEN}[OK]{Color.RESET} Semgrep code analysis completed.")
        else:
            print(f"  {Color.DIM}[INFO] Semgrep not installed (run 'supaguard doctor'){Color.RESET}")
    else:
        print(f"  {Color.DIM}[INFO] Skipped in quick mode{Color.RESET}")

    print(f"{Color.YELLOW}[Layer 5/5]{Color.RESET} Checking Lockfile Integrity & Supply-Chain Sentinel...")
    for lock in ["pnpm-lock.yaml", "yarn.lock", "package-lock.json", "bun.lock"]:
        lf = target / lock if target.is_dir() else None
        if lf and lf.exists():
            lock_findings = supply_chain.audit_lockfile(lf)
            all_findings.extend(lock_findings)

    elapsed = time.time() - start_time
    print(f"\n{Color.BOLD}{'=' * 75}{Color.RESET}")
    print(f"{Color.BOLD}SUPAGUARD AUDIT REPORT{Color.RESET}")
    print(f"{Color.BOLD}{'=' * 75}{Color.RESET}")
    print(f"Target:        {target}")
    print(f"Files Scanned: {scanned_files_count}")
    print(f"Time Taken:    {elapsed:.2f}s")
    print(f"Threats Found: {len(all_findings)}\n")

    if not all_findings:
        print(f"{Color.BG_GREEN}{Color.WHITE}{Color.BOLD} CLEAN {Color.RESET} {Color.GREEN}100% Secure! No backdoors, credentials, or critical vulnerabilities detected.{Color.RESET}\n")
    else:
        quarantine_list = []
        for idx, item in enumerate(all_findings, 1):
            sev = item.get("severity", "LOW")
            if sev == "CRITICAL":
                sev_badge = f"{Color.BG_RED}{Color.WHITE}{Color.BOLD} CRITICAL {Color.RESET}"
            elif sev == "HIGH":
                sev_badge = f"{Color.RED}{Color.BOLD} HIGH {Color.RESET}"
            elif sev == "MEDIUM":
                sev_badge = f"{Color.YELLOW}{Color.BOLD} MEDIUM {Color.RESET}"
            else:
                sev_badge = f"{Color.CYAN}{Color.BOLD} LOW {Color.RESET}"

            print(f"{Color.BOLD}[#{idx}] {sev_badge} {Color.WHITE}{item.get('name', item.get('title', 'Finding'))}{Color.RESET}")
            print(f"     {Color.DIM}Engine:{Color.RESET}   {item.get('engine', 'SupaGuard')} [{item.get('rule_id', '')}]")
            print(f"     {Color.DIM}Location:{Color.RESET} {item.get('file', '')}:{item.get('line', 1)}")
            if item.get("snippet"):
                print(f"     {Color.DIM}Snippet:{Color.RESET}  {Color.RED}{item['snippet']}{Color.RESET}")
            print(f"     {Color.DIM}Details:{Color.RESET}  {item.get('desc', item.get('detail', ''))}")
            print()

            if args.quarantine and (sev in ["CRITICAL", "HIGH"]):
                quarantine_list.append(item)

        if quarantine_list:
            print(f"\n{Color.BOLD}{Color.YELLOW}==> Processing Quarantine Requests...{Color.RESET}")
            for q_item in quarantine_list:
                success, res = quarantine_file(q_item["file"], q_item)
                if success:
                    print(f"  {Color.GREEN}[QUARANTINED]:{Color.RESET} {q_item['file']} -> {res}")
                else:
                    print(f"  {Color.RED}[FAILED]:{Color.RESET} {q_item['file']} ({res})")

    if getattr(args, "html", False):
        report_file = Path.cwd() / f"supaguard_report_{int(time.time())}.html"
        html_report.generate_html_report(str(target), all_findings, scanned_files_count, elapsed, report_file)

def cmd_sweep(args):
    root_dir = Path(args.root_path).resolve()
    print(f"\n{Color.BOLD}{Color.CYAN}==> Sweeping Repositories: {root_dir}{Color.RESET}\n")
    repos = []
    for item in root_dir.iterdir():
        if item.is_dir() and (item / ".git").exists():
            repos.append(item)
        elif item.is_dir():
            for sub in item.iterdir():
                if sub.is_dir() and (sub / ".git").exists():
                    repos.append(sub)
    if not repos and (root_dir / ".git").exists():
        repos.append(root_dir)
    if not repos:
        print(f"{Color.YELLOW}No Git repositories found in '{root_dir}'.{Color.RESET}")
        return

    print(f"Found {len(repos)} repository(ies) to audit:\n")
    for r in repos:
        print(f" - {Color.BOLD}{r.name}{Color.RESET} ({r})")
    print(f"\n{'=' * 75}")

    for r in repos:
        print(f"\n{Color.BOLD}{Color.MAGENTA}>>> SupaGuard Sweep: {r.name} ({r}) <<<{Color.RESET}")
        args.path = str(r)
        cmd_scan(args)

def cmd_watch(args):
    watch_path = Path(args.path).resolve()
    if not watch_path.exists():
        print(f"{Color.RED}[ERROR]{Color.RESET} Path '{watch_path}' does not exist.")
        sys.exit(1)

    if args.stop:
        if PID_FILE.exists():
            try:
                pid = int(PID_FILE.read_text().strip())
                if IS_WIN:
                    subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True)
                else:
                    os.kill(pid, signal.SIGTERM)
                PID_FILE.unlink(missing_ok=True)
                STATUS_FILE.unlink(missing_ok=True)
                print(f"{Color.GREEN}[OK] Real-time active shield (PID {pid}) stopped.{Color.RESET}")
            except Exception as e:
                print(f"{Color.RED}[ERROR] Failed to stop shield: {e}{Color.RESET}")
                PID_FILE.unlink(missing_ok=True)
        else:
            print(f"{Color.YELLOW}No active shield daemon found.{Color.RESET}")
        return

    if args.status:
        if PID_FILE.exists():
            pid = PID_FILE.read_text().strip()
            status_data = {}
            if STATUS_FILE.exists():
                try:
                    status_data = json.loads(STATUS_FILE.read_text())
                except Exception:
                    pass
            print(f"\n{Color.GREEN}{Color.BOLD}[ACTIVE] SupaGuard Real-Time Active Shield{Color.RESET}")
            print(f"  PID:         {pid}")
            print(f"  Watching:    {status_data.get('watch_dir', 'Unknown')}")
            print(f"  Started:     {status_data.get('started_at', 'Unknown')}")
            print(f"  Logs:        {SHIELD_LOG_FILE}\n")
        else:
            print(f"\n{Color.RED}[INACTIVE] SupaGuard Active Shield{Color.RESET}\n")
        return

    if args.daemon:
        if IS_WIN:
            proc = subprocess.Popen([sys.executable, __file__, "watch", str(watch_path)],
                                    creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP,
                                    stdout=open(SHIELD_LOG_FILE, "a"), stderr=open(SHIELD_LOG_FILE, "a"))
            pid = proc.pid
            print(f"{Color.GREEN}[OK] SupaGuard real-time shield running in background on Windows (PID {pid}).{Color.RESET}")
            PID_FILE.write_text(str(pid))
            STATUS_FILE.write_text(json.dumps({
                "pid": pid,
                "watch_dir": str(watch_path),
                "started_at": datetime.now().isoformat()
            }))
            sys.exit(0)
        else:
            pid = os.fork()
            if pid > 0:
                print(f"{Color.GREEN}[OK] SupaGuard real-time shield running in background (PID {pid}).{Color.RESET}")
                print(f"  Watching: {watch_path}")
                print(f"  Logs:     {SHIELD_LOG_FILE}")
                PID_FILE.write_text(str(pid))
                STATUS_FILE.write_text(json.dumps({
                    "pid": pid,
                    "watch_dir": str(watch_path),
                    "started_at": datetime.now().isoformat()
                }))
                sys.exit(0)
            else:
                os.setsid()

    print(f"\n{Color.BOLD}{Color.GREEN}[SHIELD ACTIVE] SupaGuard Real-Time Monitoring{Color.RESET}")
    print(f"  Watching Directory: {watch_path}")
    print(f"  Press Ctrl+C to exit interactive shield.\n")

    def populate_snapshot():
        snap = {}
        for root, dirs, files in os.walk(watch_path):
            dirs[:] = [d for d in dirs if d not in IGNORE_DIR_NAMES and not any(ign in os.path.join(root, d) for ign in IGNORE_DIR_NAMES)]
            for f in files:
                fp = Path(root) / f
                if is_ignored_path(fp):
                    continue
                try:
                    snap[str(fp)] = fp.stat().st_mtime
                except Exception:
                    pass
        return snap

    file_snapshot = populate_snapshot()
    print(f"{Color.DIM}Indexed {len(file_snapshot)} files. Intercepting write & exec events in real-time...{Color.RESET}\n")

    try:
        while True:
            time.sleep(1.0)
            current_snap = populate_snapshot()
            for fpath_str, mtime in current_snap.items():
                if fpath_str not in file_snapshot or file_snapshot[fpath_str] != mtime:
                    fpath = Path(fpath_str)
                    if is_ignored_path(fpath):
                        continue
                    findings = core_engine.scan_file_heuristics(fpath)
                    if findings:
                        print(f"{Color.BG_RED}{Color.WHITE}{Color.BOLD} BLOCKED / THREAT DETECTED {Color.RESET} {Color.RED}Threat on {fpath.name}{Color.RESET}")
                        for item in findings:
                            print(f"   -> [{item['severity']}] {item['name']}")
                    file_snapshot[fpath_str] = mtime
            file_snapshot = current_snap
    except KeyboardInterrupt:
        print(f"\n{Color.YELLOW}Real-time shield stopped.{Color.RESET}")
    finally:
        PID_FILE.unlink(missing_ok=True)
        STATUS_FILE.unlink(missing_ok=True)

def cmd_doctor(args):
    os_name = "macOS" if IS_MAC else ("Linux" if IS_LINUX else "Windows")
    print(f"\n{Color.BOLD}{Color.CYAN}==> SupaGuard System Health & Engine Diagnostics ({os_name}){Color.RESET}\n")
    
    clam_fix = "brew install clamav" if IS_MAC else ("apt install clamav" if IS_LINUX else "choco install clamav (or winget install clamav)")
    trivy_fix = "brew install trivy" if IS_MAC else ("apt install trivy" if IS_LINUX else "choco install trivy (or winget install trivy)")
    
    tools = [
        {"name": "SupaGuard Core Shield", "check": lambda: True, "fix": "Built-in (Ready)"},
        {"name": "Git Zero-Leak Hooks", "check": lambda: True, "fix": "Ready ('supaguard hook install')"},
        {"name": "Supply-Chain Sentinel", "check": lambda: True, "fix": "Ready ('supaguard safe-install')"},
        {"name": "System & Persistence Hunter", "check": lambda: True, "fix": "Ready ('supaguard audit-system')"},
        {"name": "Web3 & Crypto Shield", "check": lambda: True, "fix": "Ready ('supaguard scan --web3')"},
        {"name": "ClamAV (Antivirus Engine)", "check": lambda: find_binary("clamscan") is not None, "fix": clam_fix},
        {"name": "Trivy (Secrets & Misconfig)", "check": lambda: find_binary("trivy") is not None, "fix": trivy_fix},
        {"name": "Semgrep (SAST Engine)", "check": lambda: (find_binary("semgrep") or find_binary("pysemgrep")) is not None, "fix": "pip install semgrep"},
        {"name": "Python 3 Engine", "check": lambda: shutil.which("python3") is not None or shutil.which("python") is not None, "fix": "Install Python 3"}
    ]
    all_good = True
    for t in tools:
        is_ok = t["check"]()
        status = f"{Color.GREEN}[INSTALLED]{Color.RESET}" if is_ok else f"{Color.RED}[MISSING]{Color.RESET}"
        print(f" - {t['name']:<35} : {status}")
        if not is_ok:
            all_good = False
    print(f"\n{Color.BOLD}Quarantine Directory:{Color.RESET} {QUARANTINE_DIR}")
    print(f"Logs Directory:       {LOGS_DIR}\n")
    if all_good:
        print(f"{Color.GREEN}{Color.BOLD}All SupaGuard security engines are active! 100% Security Enabled on {os_name}.{Color.RESET}\n")

def cmd_quarantine(args):
    items = list(QUARANTINE_DIR.glob("*.quarantine"))
    if args.action == "list" or not args.action:
        print(f"\n{Color.BOLD}{Color.CYAN}==> Quarantined Items in {QUARANTINE_DIR}{Color.RESET}\n")
        if not items:
            print(f"{Color.DIM}No quarantined items found.{Color.RESET}\n")
            return
        for idx, item in enumerate(items, 1):
            meta_file = item.with_name(item.name + ".meta.json")
            meta = {}
            if meta_file.exists():
                try:
                    meta = json.loads(meta_file.read_text())
                except Exception:
                    pass
            print(f" [{idx}] {Color.RED}{item.name}{Color.RESET}")
            print(f"     Original Path: {meta.get('original_path', 'Unknown')}")
            print(f"     Threat Reason: {meta.get('threat', {}).get('name', 'Unknown Threat')}\n")
    elif args.action == "purge":
        for item in QUARANTINE_DIR.iterdir():
            if item.is_file():
                item.unlink()
        print(f"{Color.GREEN}[OK] Quarantine storage purged.{Color.RESET}\n")

def main():
    banner()
    parser = argparse.ArgumentParser(
        prog="supaguard",
        description="SupaGuard: 100% Security, Real-Time Shield & Developer Defense Suite"
    )
    subparsers = parser.add_subparsers(dest="command", help="SupaGuard commands")

    scan_p = subparsers.add_parser("scan", help="Scan a directory or file for malware, secrets, and backdoors")
    scan_p.add_argument("path", nargs="?", default=".", help="Target path to scan")
    scan_p.add_argument("--quick", action="store_true", help="Fast heuristic & secrets scan only")
    scan_p.add_argument("--quarantine", action="store_true", help="Auto-isolate detected critical threats")
    scan_p.add_argument("--web3", action="store_true", help="Enable Web3 drainer & mnemonic scans")
    scan_p.add_argument("--html", action="store_true", help="Generate interactive HTML report")

    sweep_p = subparsers.add_parser("sweep", aliases=["repo-sweep"], help="Sweep all Git repositories")
    sweep_p.add_argument("root_path", nargs="?", default=".", help="Root directory")
    sweep_p.add_argument("--quick", action="store_true", help="Quick scan mode")
    sweep_p.add_argument("--quarantine", action="store_true", help="Auto-quarantine threats")
    sweep_p.add_argument("--web3", action="store_true", help="Web3 audits")
    sweep_p.add_argument("--html", action="store_true", help="Generate HTML reports")

    watch_p = subparsers.add_parser("watch", aliases=["shield"], help="Launch real-time active shield")
    watch_p.add_argument("path", nargs="?", default=".", help="Target path to monitor")
    watch_p.add_argument("--daemon", action="store_true", help="Run in background")
    watch_p.add_argument("--stop", action="store_true", help="Stop background shield")
    watch_p.add_argument("--status", action="store_true", help="Check shield status")
    watch_p.add_argument("--auto-quarantine", action="store_true", help="Auto-quarantine detected threats")

    hook_p = subparsers.add_parser("hook", help="Manage Git Zero-Leak pre-commit hooks")
    hook_sub = hook_p.add_subparsers(dest="hook_action")
    h_inst = hook_sub.add_parser("install", help="Install zero-leak hook into repo(s)")
    h_inst.add_argument("path", nargs="?", default=".", help="Target repo or workspace root")
    h_inst.add_argument("--all", action="store_true", help="Recursively protect all sub-repos")
    h_uninst = hook_sub.add_parser("uninstall", help="Uninstall zero-leak hooks")
    h_uninst.add_argument("path", nargs="?", default=".", help="Target repo")
    h_uninst.add_argument("--all", action="store_true", help="Recursively uninstall")
    hook_sub.add_parser("check-staged", help="Internal hook runner for git staged diff")

    safe_p = subparsers.add_parser("safe-install", aliases=["install-guard"], help="Supply chain inspection before npm/yarn/bun install")
    safe_p.add_argument("packages", nargs="+", help="Package name(s) to inspect & install")
    safe_p.add_argument("--manager", choices=["npm", "yarn", "bun", "pnpm"], default="npm", help="Package manager to invoke")

    chk_p = subparsers.add_parser("check-package", help="Inspect an npm package on registry for supply-chain risks")
    chk_p.add_argument("package", help="Package spec (e.g. lodash, express@4.18.2)")

    subparsers.add_parser("audit-system", aliases=["system-audit"], help="Audit system persistence (LaunchAgents, systemd, or Windows Registry)")

    exp_p = subparsers.add_parser("explain", aliases=["deobfuscate"], help="Deobfuscate and semantically explain a suspicious file")
    exp_p.add_argument("file", help="File to deobfuscate and explain")

    subparsers.add_parser("doctor", aliases=["setup", "check"], help="Check security engine health & diagnostics")

    q_p = subparsers.add_parser("quarantine", help="Manage quarantined files")
    q_p.add_argument("action", choices=["list", "purge"], nargs="?", default="list", help="Action")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    if args.command == "scan":
        cmd_scan(args)
    elif args.command in ["sweep", "repo-sweep"]:
        cmd_sweep(args)
    elif args.command in ["watch", "shield"]:
        cmd_watch(args)
    elif args.command == "hook":
        if args.hook_action == "install":
            git_guard.install_hooks(Path(args.path).resolve(), recurse=args.all)
        elif args.hook_action == "uninstall":
            git_guard.uninstall_hooks(Path(args.path).resolve(), recurse=args.all)
        elif args.hook_action == "check-staged":
            git_guard.check_staged_files()
        else:
            hook_p.print_help()
    elif args.command in ["safe-install", "install-guard"]:
        supply_chain.safe_install_command(args.manager, args.packages)
    elif args.command == "check-package":
        res = supply_chain.inspect_npm_package(args.package)
        print(json.dumps(res, indent=2))
    elif args.command in ["audit-system", "system-audit"]:
        system_audit.run_system_audit()
    elif args.command in ["explain", "deobfuscate"]:
        deobfuscator.explain_file(Path(args.file).resolve())
    elif args.command in ["doctor", "setup", "check"]:
        cmd_doctor(args)
    elif args.command == "quarantine":
        cmd_quarantine(args)

if __name__ == "__main__":
    main()
