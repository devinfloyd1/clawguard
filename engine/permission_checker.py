"""
Permission Checker - Analyzes declared vs actual skill permissions.

Compares what a skill says it does in SKILL.md against what the code actually does.
"""

import re
from pathlib import Path
from typing import List, Set, Dict, Tuple

from .models import Finding


class PermissionChecker:
    """Check for undeclared or excessive permissions."""
    
    # Capability patterns to detect in code
    CAPABILITY_PATTERNS: Dict[str, List[Tuple[str, str]]] = {
        "file_read": [
            (r"open\s*\([^)]*['\"][ra]", "file open for reading"),
            (r"\.read\s*\(", "file read operation"),
            (r"\.read_text\s*\(", "pathlib read_text"),
            (r"\.read_bytes\s*\(", "pathlib read_bytes"),
            (r"Path\([^)]*\)\.read", "pathlib read"),
            (r"with\s+open\s*\(", "context manager file open"),
        ],
        "file_write": [
            (r"open\s*\([^)]*['\"][wa]", "file open for writing"),
            (r"\.write\s*\(", "file write operation"),
            (r"\.write_text\s*\(", "pathlib write_text"),
            (r"\.write_bytes\s*\(", "pathlib write_bytes"),
            (r"shutil\.(copy|move|rmtree)", "shutil file operations"),
            (r"os\.(remove|unlink|rmdir|mkdir|makedirs)", "os file operations"),
        ],
        "network": [
            (r"requests\.(get|post|put|delete|patch|head)", "requests HTTP"),
            (r"urllib\.(request|parse)", "urllib"),
            (r"http\.client", "http.client"),
            (r"socket\.socket", "raw socket"),
            (r"aiohttp\.", "aiohttp"),
            (r"httpx\.", "httpx"),
            (r"websocket", "websocket"),
        ],
        "subprocess": [
            (r"subprocess\.(run|call|Popen|check_output|check_call)", "subprocess"),
            (r"os\.system\s*\(", "os.system"),
            (r"os\.popen\s*\(", "os.popen"),
            (r"os\.exec[lv]", "os.exec"),
            (r"commands\.(getoutput|getstatusoutput)", "commands module"),
        ],
        "environment": [
            (r"os\.environ", "os.environ access"),
            (r"os\.getenv\s*\(", "os.getenv"),
            (r"dotenv", "dotenv"),
            (r"load_dotenv", "load_dotenv"),
        ],
        "clipboard": [
            (r"pyperclip", "pyperclip"),
            (r"clipboard", "clipboard access"),
            (r"pbcopy|pbpaste", "macOS clipboard"),
            (r"xclip|xsel", "Linux clipboard"),
        ],
        "system_info": [
            (r"platform\.(system|machine|node|release)", "platform info"),
            (r"os\.uname", "os.uname"),
            (r"socket\.gethostname", "hostname"),
            (r"getpass\.getuser", "username"),
        ],
        "keyboard_mouse": [
            (r"pynput", "pynput input capture"),
            (r"keyboard\.", "keyboard module"),
            (r"pyautogui", "pyautogui automation"),
            (r"mouse\.", "mouse module"),
        ],
        "screen_capture": [
            (r"ImageGrab", "PIL ImageGrab"),
            (r"screenshot", "screenshot"),
            (r"mss\.", "mss screen capture"),
        ],
        "crypto_wallet": [
            (r"web3\.", "web3.py"),
            (r"solana\.", "solana-py"),
            (r"bitcoin|ethereum|wallet", "crypto wallet keywords"),
        ],
    }
    
    # Keywords that indicate declared permissions in SKILL.md
    DECLARATION_KEYWORDS: Dict[str, List[str]] = {
        "file_read": [
            "file read", "reads files", "read access", "read-only",
            "file access", "read file", "load file", "parse file",
        ],
        "file_write": [
            "file write", "writes files", "write access", "creates files",
            "save file", "output file", "write to", "modify file",
        ],
        "network": [
            "network", "http", "api", "internet", "url", "fetch",
            "download", "upload", "web request", "remote", "online",
            "endpoint", "server", "client",
        ],
        "subprocess": [
            "subprocess", "command", "execute", "shell", "bash",
            "run command", "terminal", "cli", "system command",
        ],
        "environment": [
            "environment", "env var", "environ", "configuration",
            "config file", "settings",
        ],
        "clipboard": [
            "clipboard", "copy", "paste", "pasteboard",
        ],
        "system_info": [
            "system info", "platform", "hostname", "machine info",
        ],
        "keyboard_mouse": [
            "keyboard", "mouse", "input", "hotkey", "shortcut",
            "automation", "keypress",
        ],
        "screen_capture": [
            "screenshot", "screen capture", "screen grab", "display",
        ],
        "crypto_wallet": [
            "wallet", "crypto", "blockchain", "web3", "ethereum", "solana",
        ],
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
            severity = self._get_severity_for_capability(cap)
            
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
    
    def scan_code_for_capabilities(self, content: str, file_path: str) -> Set[str]:
        """
        Scan code content to detect actual capabilities used.
        
        Args:
            content: Source code content
            file_path: Path for context
            
        Returns:
            Set of capability names detected
        """
        capabilities = set()
        
        for cap_name, patterns in self.CAPABILITY_PATTERNS.items():
            for pattern, _ in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    capabilities.add(cap_name)
                    break  # Found this capability, move to next
        
        return capabilities
    
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
            
            # Map finding categories to capabilities
            if category in ["file_access"]:
                actual.add("file_read")
                actual.add("file_write")
            elif category in ["network", "data_exfiltration", "clawhavoc"]:
                actual.add("network")
            elif category in ["code_execution", "remote_access"]:
                actual.add("subprocess")
            elif category in ["environment"]:
                actual.add("environment")
            elif category in ["input_capture"]:
                actual.add("keyboard_mouse")
            elif category in ["screen_capture"]:
                actual.add("screen_capture")
            elif category in ["credential_harvest"]:
                # Could be file_read or network depending on context
                actual.add("file_read")
        
        return actual
    
    def _get_severity_for_capability(self, capability: str) -> str:
        """Get severity level for an undeclared capability."""
        # High-risk undeclared capabilities
        high_risk = {"subprocess", "network", "keyboard_mouse", "screen_capture", "crypto_wallet"}
        
        # Medium-risk
        medium_risk = {"file_write", "clipboard", "environment"}
        
        if capability in high_risk:
            return "medium"
        elif capability in medium_risk:
            return "warning"
        else:
            return "info"
