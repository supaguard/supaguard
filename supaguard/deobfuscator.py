"""
SupaGuard Semantic Explainer & Deobfuscator
Decodes base64, hex, char codes, and provides human-readable intent summaries.
"""

import re
import base64
from pathlib import Path

def decode_base64_strings(content: str):
    decoded = []
    matches = re.findall(r'(?:Buffer\.from|atob|b64decode)\s*\(\s*[\'"]([A-Za-z0-9+/=]{16,})[\'"]', content)
    for m in matches:
        try:
            raw = base64.b64decode(m).decode("utf-8", errors="ignore")
            if any(c.isprintable() for c in raw):
                decoded.append({"type": "Base64 Payload", "encoded": m[:40] + "...", "decoded": raw})
        except Exception:
            pass
    return decoded

def decode_char_codes(content: str):
    decoded = []
    matches = re.findall(r'String\.fromCharCode\s*\(\s*([\d\s,]+)\s*\)', content)
    for m in matches:
        try:
            chars = [chr(int(x.strip())) for x in m.split(",") if x.strip().isdigit()]
            raw = "".join(chars)
            decoded.append({"type": "CharCode Array", "encoded": m[:40] + "...", "decoded": raw})
        except Exception:
            pass
    return decoded

def decode_hex_escapes(content: str):
    decoded = []
    matches = re.findall(r'((?:\\x[0-9a-fA-F]{2}){4,})', content)
    for m in matches:
        try:
            raw = bytes.fromhex(m.replace("\\x", "")).decode("utf-8", errors="ignore")
            decoded.append({"type": "Hex Escapes", "encoded": m[:40] + "...", "decoded": raw})
        except Exception:
            pass
    return decoded

def explain_file(filepath: Path):
    if not filepath.exists() or not filepath.is_file():
        print(f"\033[91mFile '{filepath}' does not exist.\033[0m")
        return

    print(f"\n\033[1;96m==> SupaGuard Semantic Payload Explainer & Deobfuscator\033[0m")
    print(f"\033[2mAnalyzing: {filepath}\033[0m\n")

    content = filepath.read_text(encoding="utf-8", errors="ignore")
    b64_results = decode_base64_strings(content)
    char_results = decode_char_codes(content)
    hex_results = decode_hex_escapes(content)

    all_decoded = b64_results + char_results + hex_results

    if not all_decoded:
        print("\033[92m✓ No hidden/obfuscated binary or base64 execution payloads detected in file.\033[0m\n")
        return

    print(f"Discovered \033[1;91m{len(all_decoded)}\033[0m obfuscated payload block(s):\n")
    for idx, item in enumerate(all_decoded, 1):
        print(f"\033[1m[Block #{idx}] {item['type']}\033[0m")
        print(f"  \033[2mEncoded:\033[0m {item['encoded']}")
        print(f"  \033[1;92mDecoded Content:\033[0m\n    \033[93m{item['decoded']}\033[0m")
        
        dec = item["decoded"].lower()
        intent = []
        if "http" in dec or "curl" in dec or "wget" in dec:
            intent.append("Establishes outbound remote network request / drops secondary payload.")
        if "sh" in dec or "bash" in dec or "cmd" in dec or "exec" in dec:
            intent.append("Spawns system shell to execute arbitrary command.")
        if ".ssh" in dec or "id_rsa" in dec or "key" in dec or "token" in dec:
            intent.append("Attempts credential harvesting or sensitive key exfiltration.")
        if "rm " in dec or "unlink" in dec:
            intent.append("Performs destructive file deletion.")

        if intent:
            print(f"  \033[1;91mSemantic Analysis / Intent:\033[0m")
            for i in intent:
                print(f"    • {i}")
        print()
