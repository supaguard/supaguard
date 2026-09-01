# SupaGuard Security Guidelines for Antigravity

## Core Directive
Whenever working within repositories protected by **SupaGuard**, all AI agents and tools MUST adhere to the following security protocols:

### 1. Zero Credentials in Source Code
* NEVER write raw private keys (such as RSA or EC private key headers), high-entropy API tokens (Stripe live keys, GitHub tokens, AWS keys), or BIP-39 mnemonic seed phrases into tracked files.
* Always place credentials into `.env.local` or environment variables, and ensure `.env*` files are registered in `.gitignore`.

### 2. Mandatory Supply-Chain Vetting
* Before introducing new third-party dependencies, run `supaguard check-package <name>` to verify that the package is not freshly registered (<48h) or typosquatting a legitimate library.
* Refrain from installing packages with obfuscated `postinstall` scripts without explicit user consent.

### 3. Hook Preservation
* Do not bypass or delete `.git/hooks/pre-commit` unless specifically debugging git hook internals.
* If a commit is blocked by `SupaGuard`, resolve the root credential leak rather than forcing `git commit --no-verify`.
