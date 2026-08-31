"""
SupaGuard Web3 & Smart Contract Crypto-Shield
Scans for wallet drainers, unlimited ERC-20 approval traps, BIP-39 mnemonic leaks, and Solidity backdoors.
"""

import os
import re
from pathlib import Path

BIP39_SAMPLE_WORDS = {
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd", "abuse",
    "access", "accident", "account", "accuse", "achieve", "acid", "acoustic", "acquire", "across", "act",
    "action", "actor", "actress", "actual", "adapt", "add", "addict", "address", "adjust", "admit",
    "adult", "advance", "advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent",
    "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album", "alcohol", "alert",
    "alien", "all", "alley", "allow", "almost", "alone", "alpha", "already", "also", "alter",
    "always", "amateur", "amazing", "among", "amount", "amused", "analyst", "anchor", "ancient", "anger",
    "angle", "angry", "animal", "ankle", "announce", "annual", "another", "answer", "antenna", "antique",
    "anxiety", "any", "apart", "apology", "appear", "apple", "approve", "april", "arch", "arctic",
    "area", "arena", "argue", "arm", "armed", "armor", "army", "around", "arrange", "arrest",
    "arrive", "arrow", "art", "artefact", "artist", "artwork", "ask", "aspect", "assault", "asset",
    "assist", "assume", "asthma", "athlete", "atom", "attack", "attend", "attitude", "attract", "auction",
    "audit", "august", "aunt", "author", "auto", "autumn", "average", "avocado", "avoid", "awake",
    "aware", "away", "awesome", "awful", "awkward", "axis", "baby", "bachelor", "bacon", "badge",
    "bag", "balance", "balcony", "ball", "bamboo", "banana", "banner", "bar", "barely", "bargain",
    "barrel", "base", "basic", "basket", "battle", "beach", "bean", "beauty", "because", "become",
    "beef", "before", "begin", "behave", "behind", "believe", "below", "belt", "bench", "benefit",
    "best", "betray", "better", "between", "beyond", "bicycle", "bid", "bike", "bind", "biology",
    "bird", "birth", "bitter", "black", "blade", "blame", "blanket", "blast", "bleak", "bless",
    "blind", "blood", "blossom", "blouse", "blue", "blur", "blush", "board", "boat", "body",
    "boil", "bomb", "bone", "bonus", "book", "boost", "border", "boring", "borrow", "boss",
    "bottom", "bounce", "box", "boy", "bracket", "brain", "brand", "brass", "brave", "bread",
    "breeze", "brick", "bridge", "brief", "bright", "bring", "brisk", "broccoli", "broken", "bronze",
    "broom", "brother", "brown", "brush", "bubble", "buddy", "budget", "buffalo", "build", "bulb",
    "bulk", "bullet", "bundle", "bunker", "burden", "burger", "burst", "bus", "business", "busy",
    "butter", "buyer", "buzz", "cabbage", "cabin", "cable", "cactus", "cage", "cake", "call",
    "calm", "camera", "camp", "can", "canal", "cancel", "candy", "cannon", "canoe", "canvas",
    "canyon", "capable", "capital", "captain", "car", "carbon", "card", "cargo", "carpet", "carry",
    "cart", "case", "cash", "casino", "castle", "casual", "cat", "catalog", "catch", "category",
    "cattle", "caught", "cause", "caution", "cave", "ceiling", "celery", "cement", "census", "century"
}

WEB3_RULES = [
    {
        "id": "SG-W3-DRAINER-PERMIT-SPOOF",
        "name": "Permit / TypedData Signature Drainer Pattern",
        "severity": "CRITICAL",
        "pattern": re.compile(r"""(?:eth_signTypedData_v4|signTypedData|Permit\(|0x6e71edae)""", re.IGNORECASE),
        "desc": "Detects permit signature requests commonly leveraged in wallet asset drainers."
    },
    {
        "id": "SG-W3-DRAINER-UNLIMITED-APPROVAL",
        "name": "Hardcoded Unlimited ERC-20 Approval Trap",
        "severity": "HIGH",
        "pattern": re.compile(r"""(?:approve\s*\(\s*0x[0-9a-fA-F]{40}\s*,\s*(?:ethers\.constants\.MaxUint256|type\(uint256\)\.max|ethers\.MaxUint256|2\*\*256\s*-\s*1|0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff))"""),
        "desc": "Unconditional maximum asset approval granting third-party drainer contracts full access."
    },
    {
        "id": "SG-W3-SOLIDITY-UNPROTECTED-DELEGATECALL",
        "name": "Solidity Unprotected Assembly Delegatecall",
        "severity": "HIGH",
        "pattern": re.compile(r"""(?:delegatecall\s*\(\s*gas\(\)|assembly\s*\{[^}]*delegatecall)"""),
        "desc": "Low-level delegatecall execution inside assembly (potential proxy takeover vulnerability)."
    },
    {
        "id": "SG-W3-SOLIDITY-SELFDESTRUCT",
        "name": "Solidity Selfdestruct / Suicide Opcode",
        "severity": "HIGH",
        "pattern": re.compile(r"""\b(?:selfdestruct|suicide)\s*\("""),
        "desc": "Contract contains selfdestruct instruction which can wipe contract bytecode and funds."
    },
    {
        "id": "SG-W3-SOLIDITY-TX-ORIGIN-AUTH",
        "name": "Solidity Insecure tx.origin Authentication",
        "severity": "MEDIUM",
        "pattern": re.compile(r"""require\s*\(\s*tx\.origin\s*==\s*"""),
        "desc": "Authentication relies on tx.origin instead of msg.sender, vulnerable to phishing contract attacks."
    }
]

def scan_mnemonic_leak(content: str):
    words = re.findall(r"\b[a-z]{3,10}\b", content.lower())
    consecutive_count = 0
    start_idx = 0
    
    for i, word in enumerate(words):
        if word in BIP39_SAMPLE_WORDS:
            if consecutive_count == 0:
                start_idx = i
            consecutive_count += 1
            if consecutive_count >= 12:
                phrase = " ".join(words[start_idx:start_idx+12])
                return {
                    "severity": "CRITICAL",
                    "name": "Exposed BIP-39 Seed Phrase (12/24 Words)",
                    "snippet": f"{phrase[:30]}... (Total 12+ words)",
                    "desc": "Unencrypted crypto wallet mnemonic seed phrase detected in file."
                }
        else:
            consecutive_count = 0
    return None

def scan_web3_file(filepath: Path):
    findings = []
    if not filepath.is_file():
        return findings
    try:
        content = filepath.read_text(encoding="utf-8", errors="ignore")
        lines = content.splitlines()

        mnemonic_finding = scan_mnemonic_leak(content)
        if mnemonic_finding:
            mnemonic_finding["file"] = str(filepath)
            mnemonic_finding["line"] = 1
            mnemonic_finding["engine"] = "SupaGuard Crypto-Shield"
            mnemonic_finding["rule_id"] = "W3-MNEMONIC-LEAK"
            findings.append(mnemonic_finding)

        for rule in WEB3_RULES:
            for match in rule["pattern"].finditer(content):
                line_no = content.count("\n", 0, match.start()) + 1
                snippet = lines[line_no - 1].strip() if line_no <= len(lines) else ""
                findings.append({
                    "engine": "SupaGuard Crypto-Shield",
                    "rule_id": rule["id"],
                    "name": rule["name"],
                    "severity": rule["severity"],
                    "file": str(filepath),
                    "line": line_no,
                    "snippet": snippet[:100],
                    "desc": rule["desc"]
                })
    except Exception:
        pass
    return findings
