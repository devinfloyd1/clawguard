# ClawGuard Assumptions & Adaptations

This document tracks differences between the BUILD_SPEC.md and the actual system,
along with assumptions made during development.

## Naming: OpenClaw vs Clawdbot

**Spec says:** OpenClaw with paths like `~/.openclaw/`
**Reality:** The system is called Clawdbot with paths like `~/.clawdbot/`

**Adaptation:** ClawGuard will support BOTH naming conventions:
- Primary: `~/.clawdbot/` (current installation)
- Fallback: `~/.openclaw/` (for compatibility)

## Skills Location

**Spec says:** `~/.openclaw/skills/`
**Reality:** Skills are in `~/.npm-global/lib/node_modules/clawdbot/skills/`

**Adaptation:** ClawGuard will scan:
1. `~/.npm-global/lib/node_modules/clawdbot/skills/`
2. `/usr/lib/node_modules/clawdbot/skills/`
3. `~/.clawdbot/skills/` (if exists)
4. `~/.openclaw/skills/` (if exists)

## Skill File Structure

**Spec says:** Python-centric skills with `.py` entry points
**Reality:** Skills are markdown-centric (SKILL.md required) with optional scripts

**Adaptation:** ClawGuard will scan:
- SKILL.md files (check for embedded code blocks)
- `scripts/` directories (Python, Shell, etc.)
- `src/` directories (Python packages)
- Any .py, .sh, .js, .ts files found

## ClawHavoc IOCs

**Spec says:** Pull from Koi's published disclosure
**Reality:** No public ClawHavoc IOC database found yet

**Adaptation:** 
1. Build initial IOC database based on BUILD_SPEC patterns
2. Structure it as specified in clawhavoc_indicators.json
3. Add ability to update from remote source when available

## Log Format

**Spec says:** Session logs in plaintext or JSON
**Reality:** JSONL (JSON Lines) format in `~/.clawdbot/agents/*/sessions/`

**Adaptation:** ClawGuard log analysis will support JSONL format

---
Last updated: 2026-02-18
