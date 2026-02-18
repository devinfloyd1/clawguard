# 🛡️ ClawGuard

**Security Scanner for OpenClaw/Clawdbot Skills**

Protect yourself from malicious skill installations. ClawGuard scans skills for dangerous patterns before you install them.

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
║ Skill:     suspicious-skill                                  ║
║ Risk:      100/100 [CRITICAL] ████████████████████          ║
╚══════════════════════════════════════════════════════════════╝

CRITICAL   [CH-002] Subprocess spawning a shell
├── File: main.py:17
├── Code: subprocess.call(["/bin/bash", "-i"])
└── Action: DO NOT INSTALL. This skill contains dangerous code.
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
│   └── obfuscation_detector.py
├── reporters/
│   ├── console_reporter.py
│   ├── json_reporter.py
│   └── markdown_reporter.py
├── iocs/
│   └── clawhavoc_indicators.json  # 50 IOC patterns
└── tests/
    └── fixtures/           # Test skills
```

## IOC Database

50 indicators of compromise across categories:
- Remote access (reverse shells, C2)
- Data exfiltration
- Credential harvesting
- Code execution
- Obfuscation techniques
- Network anomalies

## Requirements

- Python 3.8+
- No external dependencies (stdlib only)

## License

MIT

---

**Built for the Clawdbot community** 🐾
