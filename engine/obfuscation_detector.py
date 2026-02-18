"""
Obfuscation Detector - Detects code obfuscation techniques.

Identifies base64 encoding, character code construction, high entropy names, etc.
"""

import base64
import math
import re
from typing import List

from .scanner import Finding


class ObfuscationDetector:
    """Detect code obfuscation techniques."""
    
    # Base64 pattern (at least 20 chars of valid base64)
    BASE64_REGEX = re.compile(r'[A-Za-z0-9+/=]{20,}')
    
    # Character code construction pattern
    CHR_PATTERN = re.compile(r'chr\s*\(\s*\d+\s*\)')
    
    # Reversed string pattern
    REVERSE_PATTERN = re.compile(r'\[\s*:\s*:\s*-1\s*\]')
    
    # String format tricks pattern
    FORMAT_TRICK = re.compile(r"f['\"].*{\s*['\"][a-z]['\"].*}.*['\"]")
    
    # Dangerous keywords that might be obfuscated
    DANGEROUS_KEYWORDS = {'exec', 'eval', 'import', 'system', 'popen', 'subprocess'}
    
    def scan(self, content: str, file_path: str) -> List[Finding]:
        """
        Scan content for obfuscation techniques.
        
        Args:
            content: File content to scan
            file_path: Relative path for reporting
            
        Returns:
            List of findings
        """
        findings = []
        lines = content.splitlines()
        
        for line_num, line in enumerate(lines, 1):
            # Check for base64-encoded code
            findings.extend(self._check_base64(line, line_num, file_path))
            
            # Check for character code construction
            findings.extend(self._check_chr_codes(line, line_num, file_path))
            
            # Check for reversed strings
            findings.extend(self._check_reversed(line, line_num, file_path))
            
            # Check for long lines (potential packed code)
            findings.extend(self._check_line_length(line, line_num, file_path))
        
        # Check for high-entropy variable names
        findings.extend(self._check_entropy(content, file_path))
        
        return findings
    
    def _check_base64(self, line: str, line_num: int, file_path: str) -> List[Finding]:
        """Check for base64-encoded potentially malicious content."""
        findings = []
        
        for match in self.BASE64_REGEX.findall(line):
            # Skip if it looks like a hash or token (common in configs)
            if len(match) < 30:
                continue
            
            # Try to decode and check if it's code
            try:
                decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
                
                # Check if decoded content contains code-like patterns
                is_code = any([
                    'import ' in decoded,
                    'def ' in decoded,
                    'class ' in decoded,
                    'exec(' in decoded,
                    'eval(' in decoded,
                    'os.system' in decoded,
                    'subprocess' in decoded,
                    '#!/' in decoded,
                ])
                
                if is_code:
                    findings.append(Finding(
                        id="OBF-001",
                        severity="critical",
                        category="obfuscation",
                        file_path=file_path,
                        line_number=line_num,
                        line_content=line.strip()[:200],
                        pattern_matched=match[:50] + "...",
                        description="Base64-encoded executable code detected",
                        recommendation="DO NOT INSTALL. Hidden code is almost always malicious.",
                        confidence="high",
                    ))
            except:
                pass  # Not valid base64 or not UTF-8
        
        return findings
    
    def _check_chr_codes(self, line: str, line_num: int, file_path: str) -> List[Finding]:
        """Check for character code construction."""
        findings = []
        
        chr_matches = self.CHR_PATTERN.findall(line)
        if len(chr_matches) >= 3:  # 3+ chr() calls in one line is suspicious
            # Try to decode the chr() calls
            try:
                numbers = re.findall(r'chr\s*\(\s*(\d+)\s*\)', line)
                decoded = ''.join(chr(int(n)) for n in numbers)
                
                # Check if decoded string is dangerous
                decoded_lower = decoded.lower()
                if any(kw in decoded_lower for kw in self.DANGEROUS_KEYWORDS):
                    severity = "critical"
                else:
                    severity = "high"
                
                findings.append(Finding(
                    id="OBF-002",
                    severity=severity,
                    category="obfuscation",
                    file_path=file_path,
                    line_number=line_num,
                    line_content=line.strip()[:200],
                    pattern_matched=f"chr() chain -> '{decoded}'",
                    description="Character code construction detected (obfuscation technique)",
                    recommendation="Review what string is being constructed from char codes.",
                    confidence="high",
                ))
            except:
                pass
        
        return findings
    
    def _check_reversed(self, line: str, line_num: int, file_path: str) -> List[Finding]:
        """Check for reversed strings hiding dangerous keywords."""
        findings = []
        
        if self.REVERSE_PATTERN.search(line):
            # Look for string literals being reversed
            string_matches = re.findall(r'[\'"]([^\'"]+)[\'"].*\[\s*:\s*:\s*-1\s*\]', line)
            
            for s in string_matches:
                reversed_s = s[::-1].lower()
                if any(kw in reversed_s for kw in self.DANGEROUS_KEYWORDS):
                    findings.append(Finding(
                        id="OBF-003",
                        severity="critical",
                        category="obfuscation",
                        file_path=file_path,
                        line_number=line_num,
                        line_content=line.strip()[:200],
                        pattern_matched=f"'{s}'[::-1] = '{s[::-1]}'",
                        description="Reversed string hiding dangerous keyword",
                        recommendation="DO NOT INSTALL. This is a known obfuscation technique.",
                        confidence="high",
                    ))
        
        return findings
    
    def _check_line_length(self, line: str, line_num: int, file_path: str) -> List[Finding]:
        """Check for excessively long lines (potential packed/obfuscated code)."""
        findings = []
        
        if len(line) > 500 and not line.strip().startswith('#'):
            findings.append(Finding(
                id="OBF-004",
                severity="medium",
                category="obfuscation",
                file_path=file_path,
                line_number=line_num,
                line_content=line.strip()[:100] + f"... ({len(line)} chars)",
                pattern_matched=f"line length: {len(line)}",
                description="Excessively long line (potential packed/obfuscated code)",
                recommendation="Very long lines often indicate minified or obfuscated code.",
                confidence="medium",
            ))
        
        return findings
    
    def _check_entropy(self, content: str, file_path: str) -> List[Finding]:
        """Check for high-entropy variable names."""
        findings = []
        
        # Extract variable names (simple heuristic)
        var_pattern = re.compile(r'\b([a-zA-Z_][a-zA-Z0-9_]{7,})\b')
        var_names = set(var_pattern.findall(content))
        
        for name in var_names:
            # Skip common patterns
            if name.startswith('__') or name.endswith('__'):
                continue
            if any(common in name.lower() for common in ['self', 'class', 'func', 'method', 'init', 'main', 'result', 'value', 'string', 'number', 'handler']):
                continue
            
            entropy = self._calculate_entropy(name)
            if entropy > 4.0:  # High entropy threshold
                findings.append(Finding(
                    id="OBF-005",
                    severity="info",
                    category="obfuscation",
                    file_path=file_path,
                    line_number=0,
                    line_content=name,
                    pattern_matched=f"entropy={entropy:.2f}",
                    description=f"High-entropy variable name: {name}",
                    recommendation="Random-looking names may indicate obfuscated code.",
                    confidence="low",
                ))
        
        return findings
    
    def _calculate_entropy(self, s: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not s:
            return 0.0
        
        freq = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        
        entropy = 0.0
        for count in freq.values():
            p = count / len(s)
            if p > 0:
                entropy -= p * math.log2(p)
        
        return entropy
