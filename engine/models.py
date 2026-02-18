"""
Data models for ClawGuard scanner.
"""

from dataclasses import dataclass, field
from typing import List


@dataclass
class Finding:
    """A single security finding."""
    id: str                    # IOC ID (e.g., "CH-001")
    severity: str              # "critical", "high", "medium", "warning", "info"
    category: str              # "data_exfiltration", "credential_harvest", etc.
    file_path: str             # Relative path within skill directory
    line_number: int           # Line where pattern was found
    line_content: str          # The actual line of code
    pattern_matched: str       # Which pattern triggered this finding
    description: str           # Human-readable explanation
    recommendation: str        # What the user should do
    confidence: str            # "high", "medium", "low"


@dataclass
class ScanResult:
    """Complete result of scanning a skill."""
    skill_name: str
    skill_path: str
    scan_timestamp: str        # ISO 8601
    scan_duration_seconds: float = 0.0
    files_scanned: int = 0
    total_lines_scanned: int = 0
    findings: List[Finding] = field(default_factory=list)
    risk_score: int = 0        # 0-100
    risk_level: str = "safe"   # "safe", "low", "medium", "high", "critical"
    summary: str = ""          # One-line summary
    ioc_database_version: str = "1.0.0"
