"""
Permission Checker - Analyzes declared vs actual skill permissions.

Compares what a skill says it does in SKILL.md against what the code actually does.
"""

import re
from typing import List, Set

from .scanner import Finding


class PermissionChecker:
    """Check for undeclared or excessive permissions."""
    
    # Permission indicators in code
    CAPABILITY_PATTERNS = {
        "file_read": [
            r"open\s*\(.*['\"]r",
            r"\.read\s*\(",
            r"Path\(.*\)\.read",
        ],
        "file_write": [
            r"open\s*\(.*['\"]w",
            r"\.write\s*\(",
            r"Path\(.*\)\.write",
            r"shutil\.(copy|move)",
        ],
        "network": [
            r"requests\.",
            r"urllib",
            r"http\.client",
            r"socket\.",
            r"aiohttp",
        ],
        "subprocess": [
            r"subprocess\.",
            r"os\.system",
            r"os\.popen",
        ],
        "environment": [
            r"os\.environ",
            r"os\.getenv",
            r"dotenv",
        ],
        "system_info": [
            r"platform\.",
            r"os\.uname",
            r"socket\.gethostname",
        ],
    }
    
    # Keywords that might indicate declared permissions in SKILL.md
    DECLARATION_KEYWORDS = {
        "file_read": ["file read", "reads files", "read access", "read-only"],
        "file_write": ["file write", "writes files", "write access", "creates files"],
        "network": ["network", "http", "api", "internet", "url", "fetch", "download", "upload"],
        "subprocess": ["subprocess", "command", "execute", "shell", "bash", "run command"],
        "environment": ["environment", "env var", "environ"],
    }
    
    def scan(self, skill_md_content: str, code_findings: List[Finding]) -> List[Finding]:
        """
        Check for undeclared permissions.
        
        Args:
            skill_md_content: Content of SKILL.md
            code_findings: Findings from other analyzers (to determine actual capabilities)
            
        Returns:
            List of permission-related findings
        """
        findings = []
        
        # Determine declared capabilities from SKILL.md
        declared = self._extract_declared_capabilities(skill_md_content)
        
        # Determine actual capabilities from findings
        actual = self._extract_actual_capabilities(code_findings)
        
        # Find undeclared capabilities
        undeclared = actual - declared
        
        for cap in undeclared:
            severity = "warning"
            if cap in ["subprocess", "network"]:
                severity = "medium"
            
            findings.append(Finding(
                id="PERM-001",
                severity=severity,
                category="undeclared_permission",
                file_path="SKILL.md",
                line_number=0,
                line_content=f"Undeclared capability: {cap}",
                pattern_matched=cap,
                description=f"Skill uses '{cap}' capability but doesn't declare it in SKILL.md",
                recommendation="Update SKILL.md to declare this capability, or remove if not needed.",
                confidence="medium",
            ))
        
        return findings
    
    def _extract_declared_capabilities(self, content: str) -> Set[str]:
        """Extract declared capabilities from SKILL.md."""
        declared = set()
        content_lower = content.lower()
        
        for cap, keywords in self.DECLARATION_KEYWORDS.items():
            if any(kw in content_lower for kw in keywords):
                declared.add(cap)
        
        return declared
    
    def _extract_actual_capabilities(self, findings: List[Finding]) -> Set[str]:
        """Determine actual capabilities from code findings."""
        actual = set()
        
        for finding in findings:
            category = finding.category
            
            # Map categories to capabilities
            if category in ["file_access"]:
                actual.add("file_read")
                actual.add("file_write")
            elif category in ["network", "data_exfiltration"]:
                actual.add("network")
            elif category in ["code_execution", "subprocess"]:
                actual.add("subprocess")
            elif category in ["environment"]:
                actual.add("environment")
        
        return actual
