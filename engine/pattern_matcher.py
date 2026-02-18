"""
Pattern Matcher - Regex and string pattern matching for IOC detection.

Scans text files for patterns defined in the IOC database.
"""

import json
import re
from pathlib import Path
from typing import List, Dict, Any

from .scanner import Finding


class PatternMatcher:
    """Matches IOC patterns against file content."""
    
    def __init__(self):
        """Load IOC patterns from database."""
        self.indicators = self._load_indicators()
        self.allowlist = self._load_allowlist()
    
    def _load_indicators(self) -> List[Dict[str, Any]]:
        """Load IOC indicators from JSON database."""
        ioc_path = Path(__file__).parent.parent / "iocs" / "clawhavoc_indicators.json"
        try:
            with open(ioc_path) as f:
                data = json.load(f)
                return data.get("indicators", [])
        except Exception as e:
            print(f"Warning: Could not load IOC database: {e}")
            return []
    
    def _load_allowlist(self) -> List[Dict[str, Any]]:
        """Load allowlist patterns."""
        path = Path(__file__).parent.parent / "iocs" / "safe_allowlist.json"
        try:
            with open(path) as f:
                data = json.load(f)
                return data.get("allowlist", [])
        except:
            return []
    
    def _is_allowlisted(self, line: str, ioc_id: str) -> bool:
        """Check if a line matches an allowlist pattern for this IOC."""
        for entry in self.allowlist:
            if ioc_id in entry.get("applies_to", []):
                pattern = entry.get("pattern", "")
                try:
                    if re.search(pattern, line):
                        return True
                except:
                    pass
        return False
    
    def _is_in_comment(self, line: str) -> bool:
        """Check if a pattern is likely in a comment."""
        stripped = line.strip()
        return stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("*")
    
    def scan(self, content: str, file_path: str) -> List[Finding]:
        """
        Scan file content for IOC patterns.
        
        Args:
            content: File content to scan
            file_path: Relative path for reporting
            
        Returns:
            List of findings
        """
        findings = []
        lines = content.splitlines()
        
        for indicator in self.indicators:
            pattern_type = indicator.get("pattern_type", "regex")
            pattern = indicator.get("pattern", "")
            
            if not pattern:
                continue
            
            for line_num, line in enumerate(lines, 1):
                try:
                    matched = False
                    
                    if pattern_type == "regex":
                        if re.search(pattern, line):
                            matched = True
                    elif pattern_type == "string_match":
                        if pattern in line:
                            matched = True
                    
                    if matched:
                        # Check allowlist
                        if self._is_allowlisted(line, indicator["id"]):
                            continue
                        
                        # Determine confidence based on context
                        confidence = "high"
                        if self._is_in_comment(line):
                            confidence = "low"
                        
                        # Determine recommendation
                        severity = indicator.get("severity", "info")
                        if severity == "critical":
                            rec = "DO NOT INSTALL. This skill contains dangerous code."
                        elif severity == "high":
                            rec = "Review carefully before installing. This pattern is suspicious."
                        elif severity == "medium":
                            rec = "Verify this is intentional and necessary for the skill."
                        else:
                            rec = "Low risk, but review if unexpected."
                        
                        finding = Finding(
                            id=indicator.get("id", "UNKNOWN"),
                            severity=severity,
                            category=indicator.get("category", "unknown"),
                            file_path=file_path,
                            line_number=line_num,
                            line_content=line.strip()[:200],  # Truncate long lines
                            pattern_matched=pattern,
                            description=indicator.get("description", ""),
                            recommendation=rec,
                            confidence=confidence,
                        )
                        findings.append(finding)
                        
                except re.error as e:
                    # Invalid regex pattern - skip
                    pass
        
        return findings
