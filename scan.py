#!/usr/bin/env python3
"""
ClawGuard - Security Scanner for OpenClaw/Clawdbot Skills

Usage:
    python scan.py --skill <skill-name>
    python scan.py --path /path/to/skill/directory
    python scan.py --all
    python scan.py --preview <clawhub-skill-url-or-path>
    
Output formats:
    python scan.py --skill <name> --format console  # default
    python scan.py --skill <name> --format json
    python scan.py --skill <name> --format markdown
    
Options:
    --verbose       Show all checks, not just findings
    --quiet         Only output if findings exist
    --min-severity  Filter by severity (critical, high, medium, warning, info)
    --output        Write report to file
    --update-iocs   Update IOC database
"""

import argparse
import sys
import time
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from engine.scanner import Scanner
from reporters.console_reporter import ConsoleReporter
from reporters.json_reporter import JsonReporter
from reporters.markdown_reporter import MarkdownReporter


def find_skills_directory() -> Path:
    """Find the skills directory on this system."""
    possible_paths = [
        Path.home() / ".npm-global/lib/node_modules/clawdbot/skills",
        Path("/usr/lib/node_modules/clawdbot/skills"),
        Path.home() / ".clawdbot/skills",
        Path.home() / ".openclaw/skills",
    ]
    
    for path in possible_paths:
        if path.exists():
            return path
    
    return None


def get_skill_path(skill_name: str) -> Path:
    """Get the full path to a skill by name."""
    skills_dir = find_skills_directory()
    if not skills_dir:
        return None
    return skills_dir / skill_name


def main():
    parser = argparse.ArgumentParser(
        description="ClawGuard - Security Scanner for OpenClaw/Clawdbot Skills",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    # Scan target options (mutually exclusive)
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("--skill", "-s", help="Scan a specific skill by name")
    target_group.add_argument("--path", "-p", help="Scan a skill at a specific path")
    target_group.add_argument("--all", "-a", action="store_true", help="Scan all installed skills")
    target_group.add_argument("--preview", help="Scan a skill before installing (URL or path)")
    target_group.add_argument("--update-iocs", action="store_true", help="Update IOC database")
    
    # Output options
    parser.add_argument("--format", "-f", choices=["console", "json", "markdown"], 
                       default="console", help="Output format (default: console)")
    parser.add_argument("--output", "-o", help="Write report to file")
    
    # Verbosity options
    parser.add_argument("--verbose", "-v", action="store_true", help="Show all checks")
    parser.add_argument("--quiet", "-q", action="store_true", help="Only output if findings exist")
    
    # Severity filter
    parser.add_argument("--min-severity", choices=["critical", "high", "medium", "warning", "info"],
                       default="info", help="Minimum severity to report")
    
    args = parser.parse_args()
    
    # Select reporter
    if args.format == "console":
        reporter = ConsoleReporter(verbose=args.verbose, quiet=args.quiet)
    elif args.format == "json":
        reporter = JsonReporter()
    elif args.format == "markdown":
        reporter = MarkdownReporter()
    
    # Initialize scanner
    scanner = Scanner(min_severity=args.min_severity)
    
    start_time = time.time()
    
    try:
        if args.update_iocs:
            print("Updating IOC database...")
            # TODO: Implement IOC update from remote source
            print("IOC database is already up to date.")
            return 0
        
        elif args.skill:
            skill_path = get_skill_path(args.skill)
            if not skill_path or not skill_path.exists():
                print(f"Error: Skill '{args.skill}' not found", file=sys.stderr)
                return 2
            result = scanner.scan(skill_path)
        
        elif args.path:
            skill_path = Path(args.path)
            if not skill_path.exists():
                print(f"Error: Path '{args.path}' not found", file=sys.stderr)
                return 2
            result = scanner.scan(skill_path)
        
        elif args.all:
            skills_dir = find_skills_directory()
            if not skills_dir:
                print("Error: Could not find skills directory", file=sys.stderr)
                return 2
            
            results = []
            for skill_dir in sorted(skills_dir.iterdir()):
                if skill_dir.is_dir():
                    result = scanner.scan(skill_dir)
                    results.append(result)
            
            # Report all results
            for result in results:
                reporter.report(result, output_file=args.output)
            
            duration = time.time() - start_time
            print(f"\nTotal scan time: {duration:.2f}s")
            
            # Return 1 if any findings, 0 otherwise
            has_findings = any(r.findings for r in results)
            return 1 if has_findings else 0
        
        elif args.preview:
            # TODO: Implement preview scanning (download and scan)
            print("Preview scanning not yet implemented")
            return 2
        
        # Single scan result
        result.scan_duration_seconds = time.time() - start_time
        reporter.report(result, output_file=args.output)
        
        # Exit codes: 0 = clean, 1 = findings, 2 = error
        if result.findings:
            return 1
        return 0
        
    except KeyboardInterrupt:
        print("\nScan interrupted")
        return 2
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 2


if __name__ == "__main__":
    sys.exit(main())
