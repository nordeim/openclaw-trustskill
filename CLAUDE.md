Core Purpose
TrustSkill is a security scanner specifically designed for OpenClaw skills. This is a defensive security tool that audits skill packages before they're installed or executed. It's essentially an antivirus/static analysis tool for the OpenClaw skill ecosystem.
Use Cases (When to Deploy)
1. Pre-installation Security Gate - Before installing any skill from unknown sources
2. Periodic Security Audits - Regular checks of already-installed skills
3. Pre-execution Validation - Before running scripts that modify the system
4. Publishing Validation - Quality gate before publishing to ClawHub (the skill marketplace)
5. CI/CD Integration - Automated security gates in pipelines
Detection Capabilities (Multi-Layered)
High Risk (🔴):
- Tainted command injection (user input → eval/exec/os.system)
- Hardcoded secrets (entropy-based + pattern matching for AWS, GitHub, OpenAI keys)
- Data exfiltration (HTTP POST to external servers/suspicious IPs)
- Destructive operations (rm -rf, shutil.rmtree)
- Credential harvesting
Medium Risk (🟡):
- Vulnerable dependencies (via OSV database - this is significant)
- Out-of-bounds file access (/etc/passwd, SSH keys)
- Code obfuscation (Base64, ROT13, packed code)
- Dynamic imports (import, importlib with variables)
- Network requests to unknown domains
Low Risk (🟢):
- Static shell commands (string literals only)
- Standard file operations
- Environment variable access
Scanning Modes (Performance vs. Accuracy Tradeoff)
| Mode | Analyzers | Speed | Accuracy |
|------|-----------|-------|----------|
| fast | Regex + Secrets + Dependencies | ⚡ | ⭐⭐⭐ |
| standard | Regex + AST + Secrets + Dependencies | ⚡ | ⭐⭐⭐⭐ |
| deep | All + Taint Analysis | 🐢 | ⭐⭐⭐⭐⭐ |
Key Insight: Secrets and Dependencies run in ALL modes because they're critical with low overhead.
Technical Architecture (v3.0 New Features)
1. Secret Detection Engine - Hybrid approach:
   - Entropy-based detection (min_entropy: 4.5, min_length: 20)
   - Pattern-based detection for known formats (AWS, GitHub, OpenAI)
2. Dependency Vulnerability Scanner - OSV (Open Source Vulnerabilities) database integration
3. Taint Analysis - Data flow tracking from user input to dangerous functions (deep mode only)
4. YAML Configuration System - Custom rules, severity overrides, whitelisting
Response Protocol
- Critical: Stop immediately
- High Risk: Manual review required, report to user, await confirmation
- Medium/Low Risk: Document, inform user, proceed if confirmed
Output Formats
- text (default) - Colorized terminal with progress bar
- json - For CI/CD integration
- markdown - For LLM review or documentation
Exit Codes
- 0: No high-risk issues
- 1: High-risk detected (for CI/CD gates)
Comparison with Previous Versions
The tool has evolved significantly:
- v1.x: Regex only
- v2.0: Added AST analysis, progress tracking, confidence scoring
- v3.0: Major leap - secrets, dependencies, taint analysis, configuration
---
Summary for the User
This is a defensive security tool for the OpenClaw skill ecosystem. It's designed to protect users from malicious skills by performing static analysis, secret detection, dependency vulnerability scanning, and taint analysis. The primary use case is as a security gate before installing or executing untrusted skills, with CI/CD integration capabilities for automated security enforcement.
TrustSkill v3.0 - Deep Analysis
Core Identity
Security scanner for OpenClaw skills — a defensive static analysis tool that audits skill packages before installation/execution. Think of it as an antivirus for the OpenClaw skill ecosystem.
Primary Use Cases
| Scenario | Purpose |
|----------|---------|
| Pre-installation | Gate before installing untrusted skills |
| Periodic audits | Regular security hygiene checks |
| Pre-execution | Validate before system-modifying scripts |
| Publishing validation | Quality gate for ClawHub submissions |
| CI/CD integration | Automated security gates |
Detection Architecture
Three-Tier Risk Classification:
| Risk | What It Catches | Response Protocol |
|------|-----------------|-------------------|
| 🔴 High | Tainted command injection, hardcoded secrets, data exfiltration, destructive ops, credential harvesting | Stop immediately |
| 🟡 Medium | Vulnerable deps (OSV), out-of-bounds file access, code obfuscation, dynamic imports, network requests | Manual review required |
| 🟢 Low | Static shell commands, standard file ops, env access | Document & proceed |
v3.0 Technical Innovations
1. Hybrid Secret Detection — Entropy-based (min 4.5, length 20) + pattern matching for AWS/GitHub/OpenAI keys
2. OSV Integration — Real-time CVE database for dependency vulnerabilities
3. Taint Analysis — Data flow tracking: user input → dangerous functions (deep mode)
4. YAML Configuration — Custom rules, severity overrides, whitelisting
Scanning Modes
| Mode | Analyzers Active | Best For |
|------|------------------|----------|
| fast | Regex + Secrets + Dependencies | Quick CI checks |
| standard | + AST | Balanced daily use |
| deep | + Taint Analysis | Pre-publish audits |
Key insight: Secrets & Dependency scanners run in all modes — critical checks with minimal overhead.
CLI Integration
source /opt/venv/bin/activate
python src/cli.py /path/to/skill --mode deep --format json
Exit code 1 = high-risk issues → blocks CI/CD pipelines.
---
Verdict: This is an essential security tool for any skill ecosystem. It prevents supply chain attacks by auditing third-party code before execution. The v3.0 additions (secrets, deps, taint) make it enterprise-grade.
