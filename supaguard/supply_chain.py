"""
SupaGuard Supply-Chain Sentinel & Package Inspector
Analyzes registry metadata, typosquatting distance, package age, and lifecycle hooks.
"""

import sys
import os
import json
import re
import ssl
import urllib.request
import urllib.error
import subprocess
from datetime import datetime, timezone
from pathlib import Path

def get_ssl_context():
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

POPULAR_PACKAGES = [
    "react", "react-dom", "express", "axios", "lodash", "dotenv", "cross-env",
    "typescript", "next", "vite", "vue", "ethers", "web3", "viem", "wagmi",
    "prisma", "tailwindcss", "jsonwebtoken", "bcrypt", "uuid", "socket.io",
    "fastify", "chalk", "commander", "yargs", "rxjs", "moment", "dayjs"
]

def levenshtein_distance(s1, s2):
    if len(s1) > len(s2):
        s1, s2 = s2, s1
    distances = range(len(s1) + 1)
    for i2, c2 in enumerate(s2):
        distances_ = [i2+1]
        for i1, c1 in enumerate(s1):
            if c1 == c2:
                distances_.append(distances[i1])
            else:
                distances_.append(1 + min((distances[i1], distances[i1 + 1], distances_[-1])))
        distances = distances_
    return distances[-1]

def inspect_npm_package(package_spec: str):
    pkg_name = package_spec.split("@")[0].strip()
    target_version = package_spec.split("@")[1].strip() if "@" in package_spec and not package_spec.startswith("@") else None
    
    if package_spec.startswith("@"):
        parts = package_spec[1:].split("@")
        pkg_name = "@" + parts[0]
        if len(parts) > 1:
            target_version = parts[1]

    print(f"\033[94m[AUDIT] Supply Chain Registry Check:\033[0m \033[1m{pkg_name}\033[0m ...")
    
    url = f"https://registry.npmjs.org/{pkg_name}"
    req = urllib.request.Request(url, headers={"User-Agent": "SupaGuard-Sentinel/1.0"})
    
    try:
        ctx = get_ssl_context()
        with urllib.request.urlopen(req, timeout=10, context=ctx) as response:
            data = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"status": "ERROR", "message": f"Package '{pkg_name}' not found on npm registry."}
        return {"status": "ERROR", "message": f"HTTP Error {e.code} connecting to npm registry."}
    except Exception as e:
        return {"status": "ERROR", "message": f"Registry connection error: {e}"}

    time_data = data.get("time", {})
    created_str = time_data.get("created")
    latest_ver = data.get("dist-tags", {}).get("latest")
    ver_to_check = target_version or latest_ver
    
    ver_data = data.get("versions", {}).get(ver_to_check, {})
    scripts = ver_data.get("scripts", {})
    
    findings = []
    
    # 1. Check Package Age (< 48 hours old)
    if created_str:
        try:
            created_dt = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
            now_dt = datetime.now(timezone.utc)
            age_hours = (now_dt - created_dt).total_seconds() / 3600
            if age_hours < 48:
                findings.append({
                    "severity": "HIGH",
                    "title": "Freshly Published Package (<48h old)",
                    "detail": f"Package was created {age_hours:.1f} hours ago ({created_str}). Elevated risk for typosquatting or payload drop."
                })
        except Exception:
            pass

    # 2. Check Typosquatting Against Popular Packages
    for pop in POPULAR_PACKAGES:
        if pkg_name != pop:
            dist = levenshtein_distance(pkg_name.lower(), pop.lower())
            if dist == 1 or (dist == 2 and len(pkg_name) > 6):
                findings.append({
                    "severity": "CRITICAL",
                    "title": f"Possible Typosquat of '{pop}'",
                    "detail": f"Package name '{pkg_name}' is strikingly similar to popular package '{pop}' (Distance: {dist})."
                })

    # 3. Check Suspicious Lifecycle Scripts
    suspicious_hooks = ["preinstall", "install", "postinstall", "prepare"]
    for hook in suspicious_hooks:
        if hook in scripts:
            hook_cmd = scripts[hook]
            sev = "HIGH"
            if re.search(r"(?:curl|wget|/dev/tcp|base64|unescape|eval\(|rm -rf)", hook_cmd, re.IGNORECASE):
                sev = "CRITICAL"
            findings.append({
                "severity": sev,
                "title": f"Suspicious Lifecycle Hook: '{hook}'",
                "detail": f"Executes script command: {hook_cmd}"
            })

    return {
        "status": "OK",
        "name": pkg_name,
        "latest_version": latest_ver,
        "version_checked": ver_to_check,
        "created": created_str,
        "homepage": data.get("homepage", "N/A"),
        "findings": findings
    }

def audit_lockfile(lockfile_path: Path):
    findings = []
    if not lockfile_path.exists():
        return findings

    content = lockfile_path.read_text(encoding="utf-8", errors="ignore")
    url_matches = re.findall(r'https?://[^\s",\']+', content)
    for url in url_matches:
        if not any(trusted in url for trusted in [
            "registry.npmjs.org", "registry.yarnpkg.com", "github.com",
            "pnpm.io", "nodejs.org", "npmjs.com"
        ]):
            findings.append({
                "severity": "HIGH",
                "title": "Untrusted / Third-Party Registry in Lockfile",
                "url": url,
                "file": str(lockfile_path)
            })
    return findings

def safe_install_command(manager: str, packages: list):
    if not packages:
        print("\033[91m[ERROR] No packages specified.\033[0m")
        return

    print(f"\n\033[1;96m==> SupaGuard Safe-Install Sentinel ({manager})\033[0m\n")
    critical_block = False

    for pkg in packages:
        if pkg.startswith("-"):
            continue
        res = inspect_npm_package(pkg)
        if res.get("status") == "ERROR":
            print(f"\033[93m[WARN] {res['message']}\033[0m")
            continue

        findings = res.get("findings", [])
        if not findings:
            print(f"  \033[92m[CLEAN] {res['name']}@{res['version_checked']}:\033[0m Verified on npm registry.")
        else:
            print(f"  \033[91m[FLAGGED] {res['name']}@{res['version_checked']}:\033[0m \033[1;91m{len(findings)} Risk(s) Flagged!\033[0m")
            for f in findings:
                sev_color = "\033[1;41;97m" if f["severity"] == "CRITICAL" else "\033[1;91m"
                print(f"     {sev_color} {f['severity']} \033[0m \033[1m{f['title']}\033[0m")
                print(f"     \033[2m{f['detail']}\033[0m")
                if f["severity"] == "CRITICAL":
                    critical_block = True
    
    if critical_block:
        print("\n\033[1;41;97m [BLOCKED BY SUPAGUARD] \033[0m Critical supply-chain risks detected! Installation aborted.")
        print("\033[2mTo bypass, invoke your package manager directly.\033[0m\n")
        sys.exit(1)

    print(f"\n\033[92mAll packages passed safety inspection. Invoking '{manager}'...\033[0m\n")
    cmd = [manager]
    if manager in ["npm", "pnpm", "bun"]:
        cmd.extend(["install"] + packages)
    elif manager == "yarn":
        cmd.extend(["add"] + packages)
    
    subprocess.run(cmd)
