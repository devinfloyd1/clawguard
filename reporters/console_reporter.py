"""
Console Reporter - Colored terminal output for scan results.
"""

from typing import Optional

from engine.scanner import ScanResult, Finding


class ConsoleReporter:
    """Report scan results to the console with colors."""
    
    # ANSI color codes
    COLORS = {
        "reset": "\033[0m",
        "bold": "\033[1m",
        "dim": "\033[2m",
        "red": "\033[91m",
        "green": "\033[92m",
        "yellow": "\033[93m",
        "blue": "\033[94m",
        "magenta": "\033[95m",
        "cyan": "\033[96m",
        "white": "\033[97m",
        "bg_red": "\033[41m",
    }
    
    SEVERITY_COLORS = {
        "critical": "bg_red",
        "high": "red",
        "medium": "yellow",
        "warning": "yellow",
        "info": "dim",
    }
    
    def __init__(self, verbose: bool = False, quiet: bool = False):
        self.verbose = verbose
        self.quiet = quiet
    
    def _c(self, color: str, text: str) -> str:
        """Apply color to text."""
        return f"{self.COLORS.get(color, '')}{text}{self.COLORS['reset']}"
    
    def _severity_color(self, severity: str) -> str:
        """Get color for severity level."""
        return self.SEVERITY_COLORS.get(severity, "white")
    
    def report(self, result: ScanResult, output_file: Optional[str] = None):
        """
        Print scan results to console.
        
        Args:
            result: Scan result to report
            output_file: Optional file to write output (ignored for console)
        """
        # If quiet and no findings, skip
        if self.quiet and not result.findings:
            return
        
        # Header
        print()
        print(self._c("cyan", "╔" + "═" * 62 + "╗"))
        print(self._c("cyan", "║") + self._c("bold", "      ClawGuard Scan Report".center(62)) + self._c("cyan", "║"))
        print(self._c("cyan", "╠" + "═" * 62 + "╣"))
        
        # Skill info
        print(self._c("cyan", "║") + f" Skill:     {result.skill_name}".ljust(62) + self._c("cyan", "║"))
        print(self._c("cyan", "║") + f" Path:      {result.skill_path[:50]}".ljust(62) + self._c("cyan", "║"))
        print(self._c("cyan", "║") + f" Scanned:   {result.scan_timestamp}".ljust(62) + self._c("cyan", "║"))
        print(self._c("cyan", "║") + f" Duration:  {result.scan_duration_seconds:.2f}s".ljust(62) + self._c("cyan", "║"))
        print(self._c("cyan", "║") + f" Files:     {result.files_scanned} files, {result.total_lines_scanned} lines".ljust(62) + self._c("cyan", "║"))
        
        # Risk score bar
        bar_filled = int(result.risk_score / 5)  # 20 char bar
        bar = "█" * bar_filled + "░" * (20 - bar_filled)
        
        risk_color = "green" if result.risk_score <= 25 else "yellow" if result.risk_score <= 50 else "red"
        risk_text = f" Risk:      {result.risk_score}/100 [{result.risk_level.upper()}] {bar}"
        print(self._c("cyan", "║") + self._c(risk_color, risk_text.ljust(62)) + self._c("cyan", "║"))
        
        print(self._c("cyan", "╚" + "═" * 62 + "╝"))
        print()
        
        if not result.findings:
            print(self._c("green", "✓ No security issues found!"))
            print()
            return
        
        # Group findings by severity
        by_severity = {}
        for f in result.findings:
            by_severity.setdefault(f.severity, []).append(f)
        
        # Print findings by severity
        for severity in ["critical", "high", "medium", "warning", "info"]:
            if severity not in by_severity:
                continue
            
            for finding in by_severity[severity]:
                color = self._severity_color(severity)
                
                # Severity badge
                badge = self._c(color, severity.upper().ljust(10))
                print(f"{badge} [{finding.id}] {finding.description}")
                print(f"├── File: {finding.file_path}:{finding.line_number}")
                print(f"├── Code: {finding.line_content}")
                print(f"├── Category: {finding.category}")
                print(f"├── Confidence: {finding.confidence}")
                print(f"└── Action: {finding.recommendation}")
                print()
        
        # Summary
        print("─" * 64)
        counts = {sev: len(by_severity.get(sev, [])) for sev in ["critical", "high", "medium", "warning", "info"]}
        summary_parts = [f"{counts[s]} {s}" for s in counts if counts[s] > 0]
        print(f"Summary: {', '.join(summary_parts)}")
        
        # Final recommendation
        if result.risk_level == "critical":
            print(self._c("red", "Recommendation: DO NOT INSTALL — Critical findings detected"))
        elif result.risk_level == "high":
            print(self._c("red", "Recommendation: HIGH RISK — Review carefully before installing"))
        elif result.risk_level == "medium":
            print(self._c("yellow", "Recommendation: MEDIUM RISK — Review findings before installing"))
        else:
            print(self._c("green", "Recommendation: Low risk — Review findings if concerned"))
        
        print("─" * 64)
        print()
