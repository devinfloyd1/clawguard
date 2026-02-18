"""
Core scanning orchestration module.

Accepts a skill directory path, enumerates files, routes to analyzers,
aggregates results, and computes risk score.
"""

from datetime import datetime
from pathlib import Path
from typing import List
import json

from .models import Finding, ScanResult
from .pattern_matcher import PatternMatcher
from .ast_analyzer import AstAnalyzer
from .network_analyzer import NetworkAnalyzer
from .obfuscation_detector import ObfuscationDetector
from .permission_checker import PermissionChecker


class Scanner:
    """Main scanner orchestrator."""
    
    # Severity weights for risk score calculation
    SEVERITY_WEIGHTS = {
        "critical": 25,
        "high": 15,
        "medium": 8,
        "warning": 3,
        "info": 1,
    }
    
    # Risk level thresholds
    RISK_THRESHOLDS = [
        (10, "safe"),
        (25, "low"),
        (50, "medium"),
        (75, "high"),
        (100, "critical"),
    ]
    
    # File extensions to scan
    SCANNABLE_EXTENSIONS = {
        ".py", ".sh", ".bash", ".js", ".ts",
        ".yaml", ".yml", ".json", ".toml",
        ".md",  # For embedded code blocks
    }
    
    def __init__(self, min_severity: str = "info"):
        """Initialize scanner with analyzers."""
        self.min_severity = min_severity
        self.pattern_matcher = PatternMatcher()
        self.ast_analyzer = AstAnalyzer()
        self.network_analyzer = NetworkAnalyzer()
        self.obfuscation_detector = ObfuscationDetector()
        self.permission_checker = PermissionChecker()
        
        # Load IOC database version
        self.ioc_version = self._load_ioc_version()
    
    def _load_ioc_version(self) -> str:
        """Load IOC database version."""
        ioc_path = Path(__file__).parent.parent / "iocs" / "clawhavoc_indicators.json"
        try:
            with open(ioc_path) as f:
                data = json.load(f)
                return data.get("version", "unknown")
        except:
            return "unknown"
    
    def scan(self, skill_path: Path) -> ScanResult:
        """
        Scan a skill directory for security issues.
        
        Args:
            skill_path: Path to the skill directory
            
        Returns:
            ScanResult with all findings and risk assessment
        """
        skill_path = Path(skill_path)
        skill_name = skill_path.name
        
        result = ScanResult(
            skill_name=skill_name,
            skill_path=str(skill_path),
            scan_timestamp=datetime.utcnow().isoformat() + "Z",
            ioc_database_version=self.ioc_version,
        )
        
        if not skill_path.exists():
            result.summary = f"Skill directory not found: {skill_path}"
            return result
        
        # Enumerate all files
        files_to_scan = self._enumerate_files(skill_path)
        result.files_scanned = len(files_to_scan)
        
        # Scan each file
        all_findings = []
        total_lines = 0
        
        for file_path in files_to_scan:
            try:
                content = file_path.read_text(errors="ignore")
                lines = content.splitlines()
                total_lines += len(lines)
                rel_path = str(file_path.relative_to(skill_path))
                
                # Run pattern matcher on all text files
                findings = self.pattern_matcher.scan(content, rel_path)
                all_findings.extend(findings)
                
                # Run AST analyzer on Python files
                if file_path.suffix == ".py":
                    ast_findings = self.ast_analyzer.scan(content, rel_path)
                    all_findings.extend(ast_findings)
                
                # Run network analyzer
                net_findings = self.network_analyzer.scan(content, rel_path)
                all_findings.extend(net_findings)
                
                # Run obfuscation detector
                obf_findings = self.obfuscation_detector.scan(content, rel_path)
                all_findings.extend(obf_findings)
                
            except Exception as e:
                # Log but continue scanning other files
                pass
        
        result.total_lines_scanned = total_lines
        
        # Check SKILL.md permissions
        skill_md = skill_path / "SKILL.md"
        if skill_md.exists():
            perm_findings = self.permission_checker.scan(
                skill_md.read_text(errors="ignore"),
                all_findings
            )
            all_findings.extend(perm_findings)
        
        # Filter by minimum severity
        severity_order = ["critical", "high", "medium", "warning", "info"]
        min_idx = severity_order.index(self.min_severity)
        filtered_findings = [
            f for f in all_findings 
            if severity_order.index(f.severity) <= min_idx
        ]
        
        # Deduplicate findings (same IOC ID, file, and line)
        seen = set()
        unique_findings = []
        for f in filtered_findings:
            key = (f.id, f.file_path, f.line_number)
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)
        
        result.findings = unique_findings
        
        # Calculate risk score
        result.risk_score = self._calculate_risk_score(unique_findings)
        result.risk_level = self._get_risk_level(result.risk_score)
        
        # Generate summary
        result.summary = self._generate_summary(result)
        
        return result
    
    def _enumerate_files(self, skill_path: Path) -> List[Path]:
        """Enumerate all scannable files in a skill directory."""
        files = []
        for item in skill_path.rglob("*"):
            if item.is_file() and item.suffix in self.SCANNABLE_EXTENSIONS:
                files.append(item)
        return files
    
    def _calculate_risk_score(self, findings: List[Finding]) -> int:
        """Calculate risk score from findings (0-100)."""
        score = 0
        for finding in findings:
            score += self.SEVERITY_WEIGHTS.get(finding.severity, 0)
        return min(100, score)  # Cap at 100
    
    def _get_risk_level(self, score: int) -> str:
        """Get risk level from score."""
        for threshold, level in self.RISK_THRESHOLDS:
            if score <= threshold:
                return level
        return "critical"
    
    def _generate_summary(self, result: ScanResult) -> str:
        """Generate one-line summary of scan results."""
        if not result.findings:
            return f"No security issues found in {result.skill_name}"
        
        # Count by severity
        counts = {}
        for f in result.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        
        parts = []
        for sev in ["critical", "high", "medium", "warning", "info"]:
            if sev in counts:
                parts.append(f"{counts[sev]} {sev}")
        
        return f"{result.skill_name}: {', '.join(parts)} findings"
