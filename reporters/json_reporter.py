"""
JSON Reporter - Machine-readable JSON output for scan results.
"""

import json
from dataclasses import asdict
from typing import Optional

from engine.models import ScanResult


class JsonReporter:
    """Report scan results as JSON."""
    
    SCHEMA_VERSION = "1.0.0"
    
    def report(self, result: ScanResult, output_file: Optional[str] = None):
        """
        Output scan results as JSON.
        
        Args:
            result: Scan result to report
            output_file: Optional file to write output
        """
        # Convert to dict
        data = {
            "schema_version": self.SCHEMA_VERSION,
            "skill_name": result.skill_name,
            "skill_path": result.skill_path,
            "scan_timestamp": result.scan_timestamp,
            "scan_duration_seconds": result.scan_duration_seconds,
            "files_scanned": result.files_scanned,
            "total_lines_scanned": result.total_lines_scanned,
            "risk_score": result.risk_score,
            "risk_level": result.risk_level,
            "summary": result.summary,
            "ioc_database_version": result.ioc_database_version,
            "findings": [
                {
                    "id": f.id,
                    "severity": f.severity,
                    "category": f.category,
                    "file_path": f.file_path,
                    "line_number": f.line_number,
                    "line_content": f.line_content,
                    "pattern_matched": f.pattern_matched,
                    "description": f.description,
                    "recommendation": f.recommendation,
                    "confidence": f.confidence,
                }
                for f in result.findings
            ],
        }
        
        json_output = json.dumps(data, indent=2)
        
        if output_file:
            with open(output_file, "w") as f:
                f.write(json_output)
            print(f"Report written to {output_file}")
        else:
            print(json_output)
