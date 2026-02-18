"""
Network Analyzer - Detects network-related security issues.

Extracts and analyzes URLs, IPs, and domains from code.
"""

import re
from typing import List, Set

from .scanner import Finding


class NetworkAnalyzer:
    """Analyze code for network-related security issues."""
    
    # Patterns for extracting network artifacts
    URL_REGEX = re.compile(r'https?://[^\s\'"<>\)\]]+')
    IP_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    DOMAIN_REGEX = re.compile(r'\b[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.[a-zA-Z]{2,}\b')
    
    # Suspicious TLDs often used for malicious domains
    SUSPICIOUS_TLDS = {'.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', '.click', '.loan'}
    
    # URL shorteners that hide true destinations
    URL_SHORTENERS = {'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'j.mp'}
    
    # Localhost addresses (safe)
    LOCALHOST = {'127.0.0.1', 'localhost', '0.0.0.0', '::1'}
    
    # RFC1918 private ranges
    PRIVATE_PREFIXES = ('10.', '172.16.', '172.17.', '172.18.', '172.19.', 
                       '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
                       '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
                       '172.30.', '172.31.', '192.168.')
    
    def scan(self, content: str, file_path: str) -> List[Finding]:
        """
        Scan content for network-related security issues.
        
        Args:
            content: File content to scan
            file_path: Relative path for reporting
            
        Returns:
            List of findings
        """
        findings = []
        lines = content.splitlines()
        
        for line_num, line in enumerate(lines, 1):
            # Check URLs
            for url in self.URL_REGEX.findall(line):
                findings.extend(self._check_url(url, line, line_num, file_path))
            
            # Check IPs
            for ip in self.IP_REGEX.findall(line):
                findings.extend(self._check_ip(ip, line, line_num, file_path))
        
        return findings
    
    def _check_url(self, url: str, line: str, line_num: int, file_path: str) -> List[Finding]:
        """Check a URL for suspicious characteristics."""
        findings = []
        url_lower = url.lower()
        
        # Check for URL shorteners
        for shortener in self.URL_SHORTENERS:
            if shortener in url_lower:
                findings.append(Finding(
                    id="NET-001",
                    severity="high",
                    category="network",
                    file_path=file_path,
                    line_number=line_num,
                    line_content=line.strip()[:200],
                    pattern_matched=url,
                    description=f"URL shortener detected: {shortener}",
                    recommendation="URL shorteners hide true destinations. Expand and verify the URL.",
                    confidence="high",
                ))
                return findings  # Don't double-report
        
        # Check for suspicious TLDs
        for tld in self.SUSPICIOUS_TLDS:
            if url_lower.endswith(tld) or f"{tld}/" in url_lower or f"{tld}?" in url_lower:
                findings.append(Finding(
                    id="NET-002",
                    severity="high",
                    category="network",
                    file_path=file_path,
                    line_number=line_num,
                    line_content=line.strip()[:200],
                    pattern_matched=url,
                    description=f"Suspicious TLD detected: {tld}",
                    recommendation="These TLDs are commonly used for malicious domains. Verify legitimacy.",
                    confidence="medium",
                ))
                break
        
        # Check for non-standard ports
        port_match = re.search(r':(\d+)(?:/|$)', url)
        if port_match:
            port = int(port_match.group(1))
            if port not in {80, 443, 8080, 8443, 3000, 5000}:
                findings.append(Finding(
                    id="NET-003",
                    severity="medium",
                    category="network",
                    file_path=file_path,
                    line_number=line_num,
                    line_content=line.strip()[:200],
                    pattern_matched=url,
                    description=f"Non-standard port detected: {port}",
                    recommendation="Unusual ports may indicate C2 communication. Verify purpose.",
                    confidence="medium",
                ))
        
        return findings
    
    def _check_ip(self, ip: str, line: str, line_num: int, file_path: str) -> List[Finding]:
        """Check an IP address for suspicious characteristics."""
        findings = []
        
        # Skip localhost
        if ip in self.LOCALHOST:
            return findings
        
        # Skip private/internal IPs
        if any(ip.startswith(prefix) for prefix in self.PRIVATE_PREFIXES):
            return findings
        
        # Public IP - flag for review
        findings.append(Finding(
            id="NET-004",
            severity="high",
            category="network",
            file_path=file_path,
            line_number=line_num,
            line_content=line.strip()[:200],
            pattern_matched=ip,
            description=f"Direct IP connection to public address: {ip}",
            recommendation="Direct IP connections bypass DNS and may indicate C2. Verify purpose.",
            confidence="medium",
        ))
        
        return findings
