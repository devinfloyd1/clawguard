"""
AST Analyzer - Python Abstract Syntax Tree analysis for deeper inspection.

Uses Python's ast module to detect dangerous patterns that regex might miss.
"""

import ast
from typing import List

from .scanner import Finding


class SecurityVisitor(ast.NodeVisitor):
    """AST visitor that checks for security issues."""
    
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.findings = []
        self.imports = set()
        self.used_names = set()
    
    def visit_Import(self, node):
        """Check for suspicious imports."""
        for alias in node.names:
            self.imports.add(alias.name)
            
            # Flag suspicious modules
            suspicious = ["ctypes", "winreg", "pickle", "marshal"]
            if alias.name in suspicious:
                self.findings.append(Finding(
                    id="AST-001",
                    severity="warning",
                    category="suspicious_import",
                    file_path=self.file_path,
                    line_number=node.lineno,
                    line_content=f"import {alias.name}",
                    pattern_matched=f"import {alias.name}",
                    description=f"Suspicious module import: {alias.name}",
                    recommendation="Verify this import is necessary for the skill's functionality.",
                    confidence="medium",
                ))
        
        self.generic_visit(node)
    
    def visit_ImportFrom(self, node):
        """Check for suspicious from imports."""
        if node.module:
            self.imports.add(node.module)
        self.generic_visit(node)
    
    def visit_Call(self, node):
        """Check for dangerous function calls."""
        func_name = self._get_func_name(node)
        
        if func_name:
            self.used_names.add(func_name)
            
            # Check for exec/eval
            if func_name in ["exec", "eval"]:
                severity = "high"
                
                # Check for nested dangerous calls (exec(base64.b64decode(...)))
                if node.args:
                    arg = node.args[0]
                    if isinstance(arg, ast.Call):
                        inner_name = self._get_func_name(arg)
                        if inner_name and "decode" in inner_name.lower():
                            severity = "critical"
                
                self.findings.append(Finding(
                    id="AST-002",
                    severity=severity,
                    category="code_execution",
                    file_path=self.file_path,
                    line_number=node.lineno,
                    line_content=f"{func_name}(...)",
                    pattern_matched=func_name,
                    description=f"Dynamic code execution via {func_name}()",
                    recommendation="Review what code is being executed. Avoid with untrusted input.",
                    confidence="high",
                ))
            
            # Check for __import__
            if func_name == "__import__":
                self.findings.append(Finding(
                    id="AST-003",
                    severity="high",
                    category="code_execution",
                    file_path=self.file_path,
                    line_number=node.lineno,
                    line_content=f"__import__(...)",
                    pattern_matched="__import__",
                    description="Dynamic module import via __import__()",
                    recommendation="Prefer static imports. Dynamic imports can load malicious code.",
                    confidence="high",
                ))
        
        self.generic_visit(node)
    
    def visit_ExceptHandler(self, node):
        """Check for bare except clauses that suppress errors."""
        if node.type is None:  # bare except:
            # Check if body is just 'pass'
            if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
                self.findings.append(Finding(
                    id="AST-004",
                    severity="warning",
                    category="error_suppression",
                    file_path=self.file_path,
                    line_number=node.lineno,
                    line_content="except: pass",
                    pattern_matched="except: pass",
                    description="Bare except with pass suppresses all errors silently",
                    recommendation="This may hide malicious activity. Use specific exception types.",
                    confidence="medium",
                ))
        
        self.generic_visit(node)
    
    def visit_Name(self, node):
        """Track name usage for unused import detection."""
        self.used_names.add(node.id)
        self.generic_visit(node)
    
    def _get_func_name(self, node) -> str:
        """Get function name from a Call node."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            return f"{self._get_attr_chain(node.func)}"
        return None
    
    def _get_attr_chain(self, node) -> str:
        """Get full attribute chain (e.g., 'os.system')."""
        if isinstance(node, ast.Attribute):
            parent = self._get_attr_chain(node.value)
            return f"{parent}.{node.attr}" if parent else node.attr
        elif isinstance(node, ast.Name):
            return node.id
        return ""
    
    def check_unused_imports(self) -> List[Finding]:
        """Check for imports that are never used."""
        findings = []
        unused = self.imports - self.used_names
        
        for module in unused:
            # Skip common utilities that might be used indirectly
            if module in ["__future__", "typing", "dataclasses"]:
                continue
            
            findings.append(Finding(
                id="AST-005",
                severity="info",
                category="unused_import",
                file_path=self.file_path,
                line_number=0,
                line_content=f"import {module}",
                pattern_matched=f"unused import: {module}",
                description=f"Module '{module}' is imported but never used",
                recommendation="Remove unused imports. Unused imports may indicate dormant payloads.",
                confidence="low",
            ))
        
        return findings


class AstAnalyzer:
    """Analyze Python files using AST for security issues."""
    
    def scan(self, content: str, file_path: str) -> List[Finding]:
        """
        Scan Python code using AST analysis.
        
        Args:
            content: Python source code
            file_path: Relative path for reporting
            
        Returns:
            List of findings
        """
        findings = []
        
        try:
            tree = ast.parse(content)
            visitor = SecurityVisitor(file_path)
            visitor.visit(tree)
            
            findings.extend(visitor.findings)
            findings.extend(visitor.check_unused_imports())
            
        except SyntaxError as e:
            # File has syntax errors - can't parse
            findings.append(Finding(
                id="AST-ERR",
                severity="info",
                category="parse_error",
                file_path=file_path,
                line_number=e.lineno or 0,
                line_content=str(e),
                pattern_matched="SyntaxError",
                description="Could not parse file - syntax error",
                recommendation="File may be intentionally malformed to evade analysis.",
                confidence="low",
            ))
        except Exception as e:
            # Other parsing error
            pass
        
        return findings
