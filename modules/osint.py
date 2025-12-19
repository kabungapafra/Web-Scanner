#!/usr/bin/env python3
"""
OSINT Reconnaissance Module
Performs subdomain enumeration, email harvesting, and technology fingerprinting.
"""

import dns.resolver
import requests
import re
import socket
from typing import Dict, List, Optional

class OSINTScanner:
    """
    Gather Open Source Intelligence.
    Features:
    - Subdomain enumeration (DNS brute force + CRT.sh)
    - Email harvesting
    - Technology stack fingerprinting
    - WHOIS lookup
    """

    def __init__(self, config: Dict, logger):
        self.config = config
        self.logger = logger

    def run_scan(self, target_domain: str) -> Dict:
        """Run OSINT scan."""
        if not self.config['modules']['osint']['enabled']:
            return {'status': 'disabled'}

        self.logger.info(f"Starting OSINT scan for {target_domain}...")
        
        results = {
            'subdomains': [],
            'emails': [],
            'technologies': [],
            'whois_info': {}
        }

        # 1. Subdomain Enumeration
        results['subdomains'] = self._enumerate_subdomains(target_domain)

        # 2. Email Harvesting
        results['emails'] = self._harvest_emails(target_domain)

        # 3. Technology Fingerprinting
        results['technologies'] = self._fingerprint_tech(target_domain)

        # 4. WHOIS (Placeholder)
        results['whois_info'] = {'registrar': 'Unknown', 'creation_date': 'Unknown'}

        return results

    def _enumerate_subdomains(self, domain: str) -> List[str]:
        """Enumerate subdomains using DNS and CRT.sh."""
        subdomains = set()
        
        # 1. CRT.sh (Certificate Transparency)
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    name_value = entry['name_value']
                    for sub in name_value.split('\n'):
                        if domain in sub:
                            subdomains.add(sub.strip())
        except Exception as e:
            self.logger.debug(f"CRT.sh lookup failed: {e}")

        # 2. DNS Brute Force (Common subdomains)
        common_subs = ['www', 'mail', 'remote', 'blog', 'webmail', 'server', 'ns1', 'ns2', 'smtp', 'secure', 'vpn', 'm', 'shop', 'ftp', 'test', 'dev']
        resolver = dns.resolver.Resolver()
        resolver.timeout = 1
        resolver.lifetime = 1

        for sub in common_subs:
            hostname = f"{sub}.{domain}"
            try:
                resolver.resolve(hostname, 'A')
                subdomains.add(hostname)
            except:
                pass

        return list(subdomains)

    def _harvest_emails(self, domain: str) -> List[str]:
        """Harvest emails from search engines (simulated)."""
        # Real implementation would scrape Google/Bing/Hunter.io
        # For now, we return a placeholder
        return []

    def _fingerprint_tech(self, domain: str) -> List[Dict]:
        """Fingerprint technology stack."""
        tech = []
        try:
            url = f"http://{domain}"
            resp = requests.get(url, timeout=5)
            headers = resp.headers
            
            # Check headers
            if 'Server' in headers:
                tech.append({'name': 'Web Server', 'value': headers['Server']})
            if 'X-Powered-By' in headers:
                tech.append({'name': 'Backend', 'value': headers['X-Powered-By']})
            
            # Check HTML content
            content = resp.text.lower()
            if 'wp-content' in content:
                tech.append({'name': 'CMS', 'value': 'WordPress'})
            if 'jquery' in content:
                tech.append({'name': 'JavaScript Library', 'value': 'jQuery'})
            if 'bootstrap' in content:
                tech.append({'name': 'UI Framework', 'value': 'Bootstrap'})
                
        except:
            pass
            
        return tech
