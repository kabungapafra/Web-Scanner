#!/usr/bin/env python3
"""
Central Results Manager for WordPress Security Scanner
Collects and organizes results from all modules
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional


class ResultsManager:
    """Manages and organizes results from all scanner modules."""

    def __init__(self, target_url: str, scan_id: str):
        self.target_url = target_url
        self.scan_id = scan_id
        self.results = {
            'target_url': target_url,
            'scan_id': scan_id,
            'scan_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'modules_run': [],
            'vulnerabilities': [],
            'warnings': [],
            'info': [],
            'module_results': {}  # Store results from each module
        }

    def add_module_result(self, module_name: str, result_data: Dict):
        """Add results from a specific module."""
        self.results['modules_run'].append(module_name)
        self.results['module_results'][module_name] = result_data

        # Extract vulnerabilities and warnings from module results
        if 'vulnerabilities' in result_data:
            self.results['vulnerabilities'].extend(result_data['vulnerabilities'])

        if 'warnings' in result_data:
            self.results['warnings'].extend(result_data['warnings'])

        if 'info' in result_data:
            self.results['info'].extend(result_data['info'])

    def get_all_results(self) -> Dict:
        """Get complete results from all modules."""
        return self.results

    def get_vulnerabilities_by_severity(self, severity: str) -> List[Dict]:
        """Get vulnerabilities filtered by severity."""
        return [v for v in self.results['vulnerabilities'] if v.get('severity') == severity]

    def get_module_result(self, module_name: str) -> Optional[Dict]:
        """Get results from a specific module."""
        return self.results['module_results'].get(module_name)

    def save_to_json(self, filename: Optional[str] = None) -> str:
        """Save all results to JSON file."""
        if not filename:
            reports_dir = Path("reports")
            reports_dir.mkdir(exist_ok=True)
            target_name = self.target_url.replace('://', '_').replace('/', '_').replace('.', '_')
            filename = reports_dir / f"scan_results_{target_name}_{self.scan_id}.json"

        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)

        return str(filename)

    def generate_summary(self) -> Dict:
        """Generate a summary of all findings."""
        summary = {
            'total_vulnerabilities': len(self.results['vulnerabilities']),
            'total_warnings': len(self.results['warnings']),
            'total_info': len(self.results['info']),
            'modules_executed': self.results['modules_run'],
            'severity_breakdown': {
                'CRITICAL': len(self.get_vulnerabilities_by_severity('CRITICAL')),
                'HIGH': len(self.get_vulnerabilities_by_severity('HIGH')),
                'MEDIUM': len(self.get_vulnerabilities_by_severity('MEDIUM')),
                'LOW': len(self.get_vulnerabilities_by_severity('LOW'))
            }
        }
        return summary