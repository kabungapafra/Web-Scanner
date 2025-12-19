#!/usr/bin/env python3
"""
Threat Intelligence Module
Integrates with NVD, WPScan, and other threat feeds.
"""

import requests
import json
from typing import Dict, List, Optional

class ThreatIntelScanner:
    """
    Fetches threat intelligence data.
    Features:
    - CVE lookup (NVD)
    - WordPress vulnerability lookup (WPScan)
    - Domain reputation check
    """

    def __init__(self, config: Dict, logger):
        self.config = config
        self.logger = logger
        self.nvd_api_key = config['modules']['threat_intel'].get('nvd_api_key')
        self.wpscan_api_key = config['modules']['threat_intel'].get('wpscan_api_key')

    def run_scan(self, target_domain: str, findings: List[Dict]) -> Dict:
        """Run threat intelligence scan."""
        if not self.config['modules']['threat_intel']['enabled']:
            return {'status': 'disabled'}

        self.logger.info(f"Gathering threat intelligence for {target_domain}...")
        
        results = {
            'cve_data': [],
            'wpscan_data': [],
            'domain_reputation': {},
            'leaked_credentials': []
        }

        # 1. Check CVEs for discovered software
        # Extract software versions from findings (e.g., "Apache 2.4.41")
        software_list = self._extract_software(findings)
        for software in software_list:
            cves = self._lookup_cve(software['name'], software['version'])
            if cves:
                results['cve_data'].extend(cves)

        # 2. Check WPScan (if WordPress)
        if self.wpscan_api_key and 'wordpress' in str(findings).lower():
            wp_vulns = self._check_wpscan(target_domain)
            results['wpscan_data'] = wp_vulns

        # 3. Domain Reputation (Placeholder for VirusTotal/Google Safe Browsing)
        results['domain_reputation'] = {'status': 'clean', 'score': 0}

        return results

    def _extract_software(self, findings: List[Dict]) -> List[Dict]:
        """Extract software names and versions from findings."""
        software = []
        # Simplified extraction logic
        for finding in findings:
            desc = finding.get('description', '').lower()
            if 'apache' in desc:
                software.append({'name': 'apache', 'version': '2.4'}) # Mock version
            if 'nginx' in desc:
                software.append({'name': 'nginx', 'version': '1.18'})
        return software

    def _lookup_cve(self, product: str, version: str) -> List[Dict]:
        """Lookup CVEs from NVD."""
        # NVD API v2 implementation would go here
        # For now, return mock data
        return [
            {
                'id': 'CVE-2021-12345',
                'severity': 'HIGH',
                'description': f'Mock vulnerability in {product} {version}'
            }
        ]

    def _check_wpscan(self, domain: str) -> List[Dict]:
        """Check WPScan API."""
        if not self.wpscan_api_key:
            return []
            
        # Real implementation would call WPScan API
        return []
