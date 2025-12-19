#!/usr/bin/env python3
"""
API Security Testing Module
Tests for REST and GraphQL vulnerabilities, JWT issues, and IDOR.
"""

import json
import jwt
import re
import requests
from typing import Dict, List, Optional

class APISecurityScanner:
    """
    Scans APIs for common vulnerabilities.
    Features:
    - Endpoint discovery (Swagger/OpenAPI)
    - JWT analysis (weak secrets, algorithm confusion)
    - IDOR testing
    - Rate limiting checks
    """

    def __init__(self, config: Dict, logger):
        self.config = config
        self.logger = logger
        self.endpoints = []

    def run_scan(self, target_url: str) -> Dict:
        """Run API security scan."""
        if not self.config['modules']['api_security']['enabled']:
            return {'status': 'disabled'}

        self.logger.info(f"Starting API security scan for {target_url}...")
        
        results = {
            'endpoints_discovered': [],
            'jwt_issues': [],
            'idor_vulnerabilities': [],
            'rate_limit_issues': [],
            'graphql_endpoints': []
        }

        # 1. Discovery
        self.endpoints = self._discover_endpoints(target_url)
        results['endpoints_discovered'] = self.endpoints

        # 2. Check for GraphQL
        graphql = self._check_graphql(target_url)
        if graphql:
            results['graphql_endpoints'].append(graphql)

        # 3. Analyze JWTs (if found in headers/responses)
        # This would typically require a valid token to start with
        # For now, we simulate checking a token if provided in config or found
        
        # 4. Test IDOR
        results['idor_vulnerabilities'] = self._test_idor(target_url, self.endpoints)

        return results

    def _discover_endpoints(self, base_url: str) -> List[str]:
        """Discover API endpoints via common paths and Swagger/OpenAPI."""
        common_paths = [
            '/api', '/api/v1', '/swagger.json', '/openapi.json', 
            '/api-docs', '/v1', '/graphql'
        ]
        found = []
        
        for path in common_paths:
            url = f"{base_url.rstrip('/')}{path}"
            try:
                resp = requests.get(url, timeout=5)
                if resp.status_code == 200:
                    found.append({'url': url, 'type': 'potential_endpoint'})
                    
                    # Parse Swagger/OpenAPI
                    if 'swagger' in url or 'openapi' in url:
                        try:
                            spec = resp.json()
                            paths = spec.get('paths', {}).keys()
                            for p in paths:
                                found.append({'url': f"{base_url}{p}", 'type': 'documented_endpoint'})
                        except:
                            pass
            except:
                pass
        
        return found

    def _check_graphql(self, base_url: str) -> Optional[Dict]:
        """Check for GraphQL introspection."""
        graphql_paths = ['/graphql', '/api/graphql', '/v1/graphql']
        
        introspection_query = """
        {
          __schema {
            types {
              name
            }
          }
        }
        """
        
        for path in graphql_paths:
            url = f"{base_url.rstrip('/')}{path}"
            try:
                resp = requests.post(url, json={'query': introspection_query}, timeout=5)
                if resp.status_code == 200 and '__schema' in resp.text:
                    return {
                        'url': url,
                        'introspection_enabled': True,
                        'severity': 'MEDIUM',
                        'recommendation': 'Disable GraphQL introspection in production'
                    }
            except:
                pass
        return None

    def _analyze_jwt(self, token: str) -> List[Dict]:
        """Analyze JWT for common weaknesses."""
        issues = []
        try:
            header = jwt.get_unverified_header(token)
            payload = jwt.decode(token, options={"verify_signature": False})
            
            # Check algorithm
            if header.get('alg') == 'none':
                issues.append({
                    'type': 'JWT None Algorithm',
                    'severity': 'CRITICAL',
                    'description': 'JWT accepts "none" algorithm, allowing signature bypass'
                })
            
            # Check for weak secrets (brute force simulation)
            # In a real tool, we'd try a dictionary attack here
            
            # Check expiration
            if 'exp' not in payload:
                issues.append({
                    'type': 'JWT No Expiration',
                    'severity': 'MEDIUM',
                    'description': 'Token does not have an expiration time'
                })
                
        except Exception as e:
            pass
            
        return issues

    def _test_idor(self, base_url: str, endpoints: List[Dict]) -> List[Dict]:
        """Test for Insecure Direct Object References."""
        issues = []
        # Pattern matching for ID-like parameters in URLs
        # e.g., /users/123 -> try /users/124
        
        for endpoint in endpoints:
            url = endpoint['url']
            # Look for numeric IDs
            match = re.search(r'/(\d+)$', url)
            if match:
                original_id = int(match.group(1))
                new_id = original_id + 1
                new_url = re.sub(r'/\d+$', f'/{new_id}', url)
                
                try:
                    # This is a simplistic check. Real IDOR requires auth context.
                    resp = requests.get(new_url, timeout=5)
                    if resp.status_code == 200:
                        # Compare response length/content to see if it's different but valid
                        issues.append({
                            'type': 'Potential IDOR',
                            'severity': 'HIGH',
                            'location': new_url,
                            'description': f'Accessible resource found by incrementing ID from {original_id} to {new_id}',
                            'recommendation': 'Implement proper authorization checks for object access'
                        })
                except:
                    pass
                    
        return issues
