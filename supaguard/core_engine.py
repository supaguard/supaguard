"""
SupaGuard Core Heuristic & AST Rule Engine
High-speed static pattern and threat analysis for codebases and repositories.
"""

import os
import re
import json
from pathlib import Path

HEURISTIC_RULES = [
    {
        "id": "SG-MAL-OBF-BASE64-EXEC",
        "name": "Obfuscated Base64 Dynamic Execution",
        "severity": "CRITICAL",
        "pattern": re.compile(r"""(?:eval|Function|exec|spawn|execSync)\s*\(\s*(?:Buffer\.from\([^)]*base64[^)]*\)|atob\(|decodeURIComponent\()""", re.IGNORECASE),
        "desc": "Dynamically executing base64-encoded strings (common payload delivery mechanism)."
    },
    {
        "id": "SG-MAL-REVERSE-SHELL",
        "name": "Reverse Shell / Socket Command Execution",
        "severity": "CRITICAL",
        "pattern": re.compile(r"""(?:/dev/tcp/[\d\.]+/|nc\s+(?:-e|-c)\s+/bin/|mkfifo\s+/tmp/|socket\.socket\(\)\.connect\(\([\'\"][0-9\.]+)""", re.IGNORECASE),
        "desc": "Reverse shell connection syntax to remote IP address."
    },
    {
        "id": "SG-MAL-REMOTE-PIPE-EXEC",
        "name": "Remote Script Download & Pipe to Shell",
        "severity": "HIGH",
        "pattern": re.compile(r"""(?:curl|wget)\s+[^|;\n]+(?:\|\s*(?:bash|sh|zsh)|>\s*/tmp/[^;\n]+\s*&&\s*(?:sh|bash))""", re.IGNORECASE),
        "desc": "Direct piping of remote web payloads into a system shell.",
        "skip_comments_and_docs": True
    },
    {
        "id": "SG-MAL-OBF-CHARCODE-EVAL",
        "name": "Character Code Obfuscated Eval",
        "severity": "HIGH",
        "pattern": re.compile(r"""eval\s*\(\s*String\.fromCharCode\s*\(""", re.IGNORECASE),
        "desc": "Obfuscating commands using character code arrays inside eval()."
    },
    {
        "id": "SG-MAL-PYTHON-EXEC-PAYLOAD",
        "name": "Python Compressed/Encoded Payload Execution",
        "severity": "CRITICAL",
        "pattern": re.compile(r"""exec\s*\(\s*(?:base64\.b64decode|zlib\.decompress|codecs\.decode)\s*\(""", re.IGNORECASE),
        "desc": "Executing compressed/encoded binary blobs via Python exec()."
    },
    {
        "id": "SG-MAL-WEB3-DRAINER-HOOK",
        "name": "Suspicious Web3 Provider Hijacking",
        "severity": "HIGH",
        "pattern": re.compile(r"""(?:window\.ethereum\._request|window\.ethereum\.sendAsync)\s*=\s*function""", re.IGNORECASE),
        "desc": "Overriding browser Web3 provider methods to hijack crypto transactions."
    },
    {
        "id": "SG-SEC-PRIVATE-KEY-UNENCRYPTED",
        "name": "Exposed Raw RSA/EC Private Key",
        "severity": "HIGH",
        "pattern": re.compile(r"""-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"""),
        "desc": "Raw unencrypted private key located in file.",
        "skip_docs": True
    },
    {
        "id": "SG-SEC-HARDCODED-SECRET-TOKEN",
        "name": "Hardcoded High-Entropy API Secret",
        "severity": "HIGH",
        "pattern": re.compile(r"""(?i)(?:sk_live_[0-9a-zA-Z]{24,}|ghp_[0-9a-zA-Z]{36}|xoxb-[0-9a-zA-Z]{24,}|AIzaSy[0-9a-zA-Z_-]{33})"""),
        "desc": "Live production secret token (Stripe, GitHub, Slack, Google API) found in file."
    },
    {
        "id": "SG-MAL-GIT-HOOK-SUSPICIOUS",
        "name": "Suspicious Code in Git Hook",
        "severity": "HIGH",
        "pattern": re.compile(r"""(?:curl|wget|nc|python -c|bash -i)\s+""", re.IGNORECASE),
        "desc": "Git lifecycle hook triggering network requests or shell escapes.",
        "path_filter": re.compile(r"""\.git/hooks/""")
    }
]

DOC_EXTENSIONS = {".md", ".markdown", ".rst", ".txt"}

def scan_file_heuristics(filepath: Path):
    """Scans a single file against SupaGuard's built-in rule definitions."""
    findings = []
    try:
        if not filepath.is_file() or filepath.is_symlink():
            return findings
        if filepath.stat().st_size > 5 * 1024 * 1024:
            return findings
        
        is_doc = filepath.suffix.lower() in DOC_EXTENSIONS
        
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            lines = content.splitlines()

            if filepath.name == "package.json":
                findings.extend(check_package_json(filepath, content))

            for rule in HEURISTIC_RULES:
                if "path_filter" in rule and not rule["path_filter"].search(str(filepath)):
                    continue
                if is_doc and rule.get("skip_docs", False):
                    continue
                
                matches = list(rule["pattern"].finditer(content))
                for match in matches:
                    match_pos = match.start()
                    line_no = content.count("\n", 0, match_pos) + 1
                    snippet = lines[line_no - 1].strip() if line_no <= len(lines) else ""
                    
                    # Ignore comment lines for remote pipe execution rules (e.g. usage instructions in headers)
                    if rule.get("skip_comments_and_docs", False):
                        if is_doc or snippet.startswith("#") or snippet.startswith("//") or snippet.startswith("/*") or snippet.startswith("*"):
                            continue

                    if len(snippet) > 120:
                        snippet = snippet[:117] + "..."
                    findings.append({
                        "engine": "SupaGuard Heuristic",
                        "rule_id": rule["id"],
                        "name": rule["name"],
                        "severity": rule["severity"],
                        "file": str(filepath),
                        "line": line_no,
                        "snippet": snippet,
                        "desc": rule["desc"]
                    })
    except Exception:
        pass
    return findings

def check_package_json(filepath: Path, content: str):
    findings = []
    try:
        data = json.loads(content)
        scripts = data.get("scripts", {})
        for hook in ["preinstall", "postinstall", "install", "prepare"]:
            if hook in scripts:
                cmd = scripts[hook]
                if re.search(r"(?:curl|wget|base64|/dev/tcp|eval\(|unescape)", cmd, re.IGNORECASE):
                    findings.append({
                        "engine": "SupaGuard Supply-Chain",
                        "rule_id": "SUPPLY-CHAIN-LIFECYCLE-HOOK",
                        "name": f"Suspicious '{hook}' Script in package.json",
                        "severity": "CRITICAL",
                        "file": str(filepath),
                        "line": 1,
                        "snippet": f'"{hook}": "{cmd}"',
                        "desc": f"Package lifecycle hook executes suspicious network/eval command: {cmd}"
                    })
    except Exception:
        pass
    return findings
