---
name: supaguard
description: Autonomous security auditing, git pre-commit zero-leak protection, supply-chain package inspection, and real-time threat defense using SupaGuard. Activate this skill whenever auditing code for vulnerabilities, inspecting dependencies, managing git hooks, or running system security scans.
---

# SupaGuard Antigravity Skill Guide

This skill equips Antigravity AI agents with autonomous security capabilities to inspect repositories, enforce zero-leak commits, sandbox new dependencies, and detect logic-based backdoors.

---

## 1. Quick Capabilities Matrix for Agents

| Workflow | Command to Execute | Expected Agent Action |
|---|---|---|
| **Repository Audit** | `supaguard scan <path> --quick` | Scan codebase for secrets, backdoors, and exposed keys before editing or committing code. |
| **Deep Full Audit** | `supaguard scan <path> --html` | Run full 5-layer audit (Heuristics + ClamAV + Trivy + Semgrep + Lockfile) and produce visual HTML report. |
| **Web3 Security Audit** | `supaguard scan <path> --web3` | Check Solidity contracts, permit signatures (`eth_signTypedData_v4`), and mnemonic seed phrase leaks. |
| **Git Zero-Leak Hooks** | `supaguard hook install .` | Install sub-15ms pre-commit hooks to block accidental credential pushes to GitHub. |
| **Supply-Chain Guard** | `supaguard check-package <pkg>` | Inspect npm registry package creation date, typosquat distance, and lifecycle scripts (`postinstall`). |
| **Safe Package Install** | `supaguard safe-install <pkg...>` | Verify package safety before running `npm install` or `bun add`. |
| **Payload Deobfuscator** | `supaguard explain <file>` | Unpack base64/hex obfuscated scripts and generate plain-English risk summaries. |
| **macOS System Hunter** | `supaguard audit-system` | Audit LaunchDaemons, LaunchAgents, and shell startup aliases for stealth persistence. |

---

## 2. Agent Autonomous Workflows

### Workflow A: Pre-Commit Security Assurance
When preparing a `git commit` on behalf of the user:
1. Verify if hooks are installed: `supaguard hook install .`
2. Run a fast staged check: `supaguard hook check-staged`
3. If any `CRITICAL` or `HIGH` severity item is flagged, stop immediately and explain the finding to the user before committing.

### Workflow B: Safe Dependency Addition
When adding a third-party npm, yarn, or bun package requested by the user:
1. Run `supaguard check-package <pkg_name>`.
2. Ensure the package is not a typosquat (e.g. `crossenv` vs `cross-env`) and does not contain unauthorized remote curl/bash executions in its `preinstall` or `postinstall` hooks.
3. If verified clean, proceed with `supaguard safe-install <pkg_name>`.

### Workflow C: Deobfuscating Suspicious Files
If an unknown or obfuscated file is discovered in the workspace:
1. Run `supaguard explain <path/to/file>`.
2. Inspect the decoded payload and intent breakdown.
3. If malicious, use `supaguard scan <dir> --quarantine` to safely isolate the file to `~/.supaguard/quarantine/`.
