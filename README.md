<p align="center">
  <h1 align="center">🛡️⚡ SUPAGUARD</h1>
  <p align="center">
    <strong>100% Security & Multi-Layer Developer Defense Suite</strong><br>
    Universal Antivirus, Real-Time Active Shield, Supply-Chain Sentinel & Git Zero-Leak Blocker.
  </p>
  <p align="center">
    <a href="https://npmjs.com/package/supaguard"><img src="https://img.shields.io/npm/v/supaguard.svg?color=indigo&style=flat-square" alt="npm version" /></a>
    <a href="https://pypi.org/project/supaguard"><img src="https://img.shields.io/pypi/v/supaguard.svg?color=blue&style=flat-square" alt="PyPI version" /></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green.svg?style=flat-square" alt="License" /></a>
    <a href="https://github.com/supaguard/supaguard/actions"><img src="https://img.shields.io/badge/build-passing-brightgreen.svg?style=flat-square" alt="Build Status" /></a>
  </p>
</p>

---

## ⚡ Overview

**SupaGuard** is a developer-first, multi-engine security suite built to safeguard local codebases, microservices, and smart contract repositories. It bridges the gap between binary-level antivirus tools (ClamAV) and developer-focused security engines (Trivy, Semgrep, AST heuristics), delivering real-time defense against malicious payloads, backdoor injections, exposed credentials, and supply-chain attacks.

```mermaid
graph TD
    SG[SupaGuard CLI] --> Core[5-Layer Security Engine]
    SG --> Git[Git Zero-Leak Guard]
    SG --> Supply[Supply-Chain Sentinel]
    SG --> Sys[macOS Persistence Hunter]
    SG --> Web3[Web3 Crypto-Shield]
    SG --> Dash[Interactive HTML Scorecards]

    Core --> H[AST & Heuristic Signatures]
    Core --> C[ClamAV Binary Signatures]
    Core --> T[Trivy CVEs & Secrets]
    Core --> S[Semgrep SAST Code Analyzer]
    Core --> L[Lockfile Poisoning Sentinel]
```

---

## 🚀 Quick Start (Zero-Friction Install)

### 1. Instant Run via NPX (Zero-Install)
```bash
# Run immediate scan on current project
npx supaguard scan .

# Generate interactive dark-mode HTML security report
npx supaguard scan . --html
```

### 2. Global Install via NPM
```bash
npm install -g supaguard
supaguard doctor
```

### 3. One-Liner Install Script (Curl / Wget)
```bash
# Using curl:
curl -fsSL https://raw.githubusercontent.com/supaguard/supaguard/main/install.sh | bash

# Using wget:
wget -qO- https://raw.githubusercontent.com/supaguard/supaguard/main/install.sh | bash
```

### 4. Python Package via Pip
```bash
pip install supaguard
# or with pipx:
pipx install supaguard
```

---

## 🛡️ Key Features

### 1. 🪝 Sub-15ms Git Zero-Leak Pre-Commit Hooks
Prevent leaked credentials, Stripe live keys, AWS secrets, Google service accounts, or backdoors from ever touching Git history or GitHub remotes.
```bash
# Protect current repository
supaguard hook install .

# Protect all Git repositories across your entire workspace
supaguard hook install --all
```

### 2. 📦 Supply-Chain & Safe-Install Sentinel
Inspects packages before executing `npm install`, `yarn add`, `bun add`, or `pnpm add`.
* **Typosquatting Detection:** Flags packages mimicking popular libraries (e.g. `crossenv` vs `cross-env`).
* **Freshness & Age Checks:** Flags newly published packages (<48 hours old).
* **Lifecycle Script Sandboxing:** Unpacks and decodes obfuscated `preinstall`/`postinstall` scripts before execution.
```bash
# Inspect and install safely
supaguard safe-install express react lodash

# Standalone registry inspection
supaguard check-package crossenv
```

### 3. 🌐 Web3 & Smart Contract Crypto-Shield
* Detects stealth `eth_signTypedData_v4` permit drainer patterns and unlimited ERC-20 token approval traps (`approve(MaxUint256)`).
* Scans files and shell history (`.zsh_history`) for unencrypted 12/24-word BIP-39 mnemonic seed phrases.
* Audits Solidity contracts for hidden ownership backdoors and unsafe assembly `delegatecall` opcodes.
```bash
supaguard scan ./web3 --web3
```

### 4. 🔍 Semantic Explainer & Deobfuscator
Unpacks character code arrays, base64 strings, and hex escapes, providing a plain-English explanation of payload intent.
```bash
supaguard explain suspicious-script.js
```

### 5. 🍏 macOS Persistence & System Hunter
Scans `/Library/LaunchDaemons`, `~/Library/LaunchAgents`, crontabs, and shell startup files (`~/.zshrc`, `~/.bashrc`) for unauthorized background daemons and alias hijacking.
```bash
supaguard audit-system
```

### 6. 👁️ Real-Time Active Shield (Background Daemon)
Monitors files in real time and intercepts write/execution events instantly.
```bash
# Start background shield
supaguard watch /path/to/project --daemon

# Check shield status
supaguard watch --status

# Stop shield
supaguard watch --stop
```

### 7. 📊 Interactive Dark-Mode HTML Scorecards
Generates a standalone, shareable HTML security report with posture grades (A+ to F), radar risk charts, and 1-click remediation details.
```bash
supaguard scan . --html
```

---

## 🤖 Antigravity AI Development Integration

SupaGuard includes first-class support for **Google Antigravity** AI development workflows.

### Included Antigravity Customizations
* **Antigravity Skill:** `.agents/skills/supaguard/SKILL.md` (Enables AI agents to autonomously audit security posture, protect commits, and sandbox third-party packages).
* **Antigravity Rule:** `.agents/rules/supaguard-security.md` (Enforces zero credential leakage during agent pair programming).

To activate in any Antigravity project, simply copy the `.agents/` folder into your repository root.

---

## 📋 Command Reference Matrix

| Command | Arguments / Flags | Description |
|---|---|---|
| `supaguard scan` | `[path] [--quick] [--html] [--web3] [--quarantine]` | Run multi-layer scan on files or directories |
| `supaguard sweep` | `[root_path] [--quick] [--html] [--web3]` | Discover and audit all Git repositories under a path |
| `supaguard watch` | `[path] [--daemon] [--status] [--stop]` | Launch real-time background file-system shield |
| `supaguard hook install` | `[path] [--all]` | Install sub-15ms pre-commit zero-leak hook |
| `supaguard hook uninstall`| `[path] [--all]` | Remove SupaGuard Git hooks |
| `supaguard safe-install` | `<pkg...> [--manager npm\|yarn\|bun\|pnpm]` | Audit dependencies for supply-chain risks before install |
| `supaguard check-package`| `<pkg>` | Inspect npm registry metadata & typosquats |
| `supaguard audit-system` | *(none)* | Audit macOS LaunchAgents, LaunchDaemons, and shell profiles |
| `supaguard explain` | `<file>` | Deobfuscate and semantically explain a payload |
| `supaguard doctor` | *(none)* | Verify installation of underlying engines (ClamAV, Trivy, Semgrep) |
| `supaguard quarantine` | `[list\|purge]` | Manage quarantined threat files |

---

## 🔒 Engine Diagnostic Health Check

Run `supaguard doctor` to check the status of all security engines:
```text
 • SupaGuard Core Shield               : INSTALLED ✓
 • Git Zero-Leak Hooks                 : INSTALLED ✓
 • Supply-Chain Sentinel               : INSTALLED ✓
 • System & Persistence Hunter         : INSTALLED ✓
 • Web3 & Crypto Shield                : INSTALLED ✓
 • ClamAV (Antivirus Engine)           : INSTALLED ✓
 • Trivy (Secrets & Misconfig)         : INSTALLED ✓
 • Semgrep (SAST Engine)               : INSTALLED ✓
 • Python 3 Engine                     : INSTALLED ✓
```

---

## 📄 License

SupaGuard is licensed under the [MIT License](LICENSE).
