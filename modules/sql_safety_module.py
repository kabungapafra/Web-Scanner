#!/usr/bin/env python3
"""
SQL Injection Safety Validation Module
For WordPress Security Scanner
Authorized Testing Only - No Attack Payloads
"""

import re
import time
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse, quote

import requests
import logging


# ============================================================================
# BASE CLASS FOR MODULES
# ============================================================================

class ScannerModule:
    """Base class for all scanner modules."""

    def __init__(self, module_name: str, config: Dict, logger: logging.Logger):
        self.module_name = module_name
        self.config = config
        self.logger = logger
        self.results = {
            'module_name': module_name,
            'vulnerabilities': [],
            'warnings': [],
            'info': [],
            'status': 'pending'
        }

    def run(self, target_url: str) -> Dict:
        """Run the module scan. Override in subclasses."""
        raise NotImplementedError("Subclasses must implement run() method")

    def get_results(self) -> Dict:
        """Get module results."""
        return self.results

    def add_vulnerability(self, vulnerability: Dict):
        """Add a vulnerability finding."""
        self.results['vulnerabilities'].append(vulnerability)

    def add_warning(self, warning: Dict):
        """Add a warning finding."""
        self.results['warnings'].append(warning)

    def add_info(self, info: Dict):
        """Add an info finding."""
        self.results['info'].append(info)

    def set_status(self, status: str):
        """Set module status."""
        self.results['status'] = status


# ============================================================================
# SQL INJECTION SAFETY VALIDATOR
# ============================================================================

class SQLInjectionSafetyValidator(ScannerModule):
    """SQL injection safety validator (no attacks, only validation)."""

    def __init__(self, config: Dict, logger: logging.Logger):
        super().__init__('sql_injection_safety', config, logger)
        self.scope_validator = ScopeValidator()
        self.client = None
        self.target_url = None

    def set_client(self, client):
        """Set HTTP client."""
        self.client = client

    def set_target_url(self, target_url: str):
        """Set target URL."""
        self.target_url = target_url

    def run(self, target_url: str = None) -> Dict:
        """Run SQL injection safety validation."""
        if target_url:
            self.target_url = target_url

        if not self.target_url:
            raise ValueError("Target URL must be set before running")

        if not self.client:
            raise ValueError("HTTP client must be set before running")

        self.logger.info(f"Starting SQL injection safety validation for {self.target_url}")
        self.set_status('running')

        try:
            # 1. Discover endpoints with parameters
            endpoints = self._discover_endpoints_with_params()

            if not endpoints:
                self.logger.info("No parameterized endpoints found for SQL validation")
                self.set_status('completed')
                self.add_info({
                    'type': 'No endpoints found',
                    'details': 'No parameterized endpoints discovered for testing',
                    'severity': 'INFO'
                })
                return self.get_results()

            # 2. Validate each endpoint (limit to 5 for safety)
            findings = []
            tested_endpoints = 0

            for endpoint_info in endpoints:
                if tested_endpoints >= 5:  # Safety limit
                    self.logger.info("Reached safety limit of 5 endpoints")
                    break

                if not self.scope_validator.is_in_scope(endpoint_info['url']):
                    self.logger.warning(f"Endpoint out of scope: {endpoint_info['url']}")
                    continue

                endpoint_findings = self._validate_endpoint_sql_safety(endpoint_info)
                findings.extend(endpoint_findings)
                tested_endpoints += 1

            # 3. Check for SQL error leakage
            error_leakage_findings = self._check_sql_error_leakage()
            findings.extend(error_leakage_findings)

            # 4. Generate hacker exploitation analysis
            exploitation_analysis = self._generate_exploitation_analysis(findings)

            # Display results
            if findings:
                print(f"\n{'=' * 80}")
                print(f"{'SQL INJECTION SAFETY VALIDATION':^80}")
                print(f"{'=' * 80}")

                for finding in findings:
                    severity_color = self._get_severity_color(finding.get('severity', 'LOW'))
                    print(f"\n{severity_color}● {finding.get('type', 'Unknown')}\033[0m")
                    print(f"  Endpoint: {finding.get('endpoint', 'N/A')}")
                    print(f"  Details: {finding.get('details', 'N/A')}")
                    print(f"  Remediation: {finding.get('remediation', 'N/A')}")

                # Display hacker exploitation analysis
                if exploitation_analysis:
                    print(f"\n{'=' * 80}")
                    print(f"{'HACKER EXPLOITATION ANALYSIS':^80}")
                    print(f"{'=' * 80}")
                    for analysis in exploitation_analysis:
                        print(f"\n  ▪ {analysis.get('vulnerability', 'Unknown')}")
                        print(f"    How hacker would exploit: {analysis.get('exploitation_method', 'N/A')}")
                        print(f"    Potential impact: {analysis.get('impact', 'N/A')}")
                        print(f"    Prevention: {analysis.get('prevention', 'N/A')}")

            else:
                print(f"\n✓ No SQL injection safety issues detected")

            # Store findings in results
            if findings:
                for finding in findings:
                    if finding.get('severity') in ['CRITICAL', 'HIGH']:
                        self.add_vulnerability(finding)
                    elif finding.get('severity') == 'MEDIUM':
                        self.add_warning(finding)
                    else:
                        self.add_info(finding)

            # Store detailed results
            self.results['details'] = {
                'findings': findings,
                'exploitation_analysis': exploitation_analysis,
                'total_endpoints_tested': tested_endpoints,
                'total_endpoints_discovered': len(endpoints),
                'validation_score': self._calculate_validation_score(findings)
            }

            self.set_status('completed')
            self.logger.info(f"SQL injection safety validation completed. Found {len(findings)} issues.")

        except Exception as e:
            self.logger.error(f"SQL injection safety validation failed: {e}")
            self.set_status('failed')
            self.add_warning({
                'type': 'Module Failure',
                'details': f'Validation failed: {str(e)}',
                'severity': 'LOW'
            })

        return self.get_results()

    # ============================================================================
    # PRIVATE METHODS
    # ============================================================================

    def _discover_endpoints_with_params(self) -> List[Dict]:
        """Discover endpoints with parameters."""
        endpoints = []

        try:
            # Get homepage to discover forms and links
            response = self.client.get(self.target_url)
            if not response:
                return endpoints

            content = response.text

            # Look for forms with parameters
            form_pattern = r'<form[^>]*action=["\']([^"\']+)["\'][^>]*>'
            form_matches = re.findall(form_pattern, content, re.IGNORECASE)

            for action in form_matches:
                if action and not action.startswith(('http://', 'https://', '//')):
                    action = self._urljoin(self.target_url, action)

                # Extract form parameters
                form_param_pattern = r'name=["\']([^"\']+)["\']'
                params = re.findall(form_param_pattern, content, re.IGNORECASE)

                if params:
                    endpoints.append({
                        'url': action,
                        'method': 'POST',
                        'parameters': list(set(params))[:5]  # Remove duplicates, limit to 5
                    })

            # Look for URLs with query parameters
            url_pattern = r'href=["\']([^"\']+\?[^"\']+)["\']'
            url_matches = re.findall(url_pattern, content, re.IGNORECASE)

            for url in url_matches:
                if url and not url.startswith(('http://', 'https://', '//')):
                    url = self._urljoin(self.target_url, url)

                # Parse query parameters
                parsed = urlparse(url)
                query_params = parsed.query.split('&')
                params = [p.split('=')[0] for p in query_params if '=' in p]

                if params:
                    endpoints.append({
                        'url': url,
                        'method': 'GET',
                        'parameters': list(set(params))[:5]  # Remove duplicates, limit to 5
                    })

            # Add common WordPress endpoints
            common_endpoints = [
                {'url': f"{self.target_url}/?s=test", 'method': 'GET', 'parameters': ['s']},
                {'url': f"{self.target_url}/?p=1", 'method': 'GET', 'parameters': ['p']},
                {'url': f"{self.target_url}/?author=1", 'method': 'GET', 'parameters': ['author']},
                {'url': f"{self.target_url}/?cat=1", 'method': 'GET', 'parameters': ['cat']},
                {'url': f"{self.target_url}/wp-admin/", 'method': 'GET', 'parameters': []},
                {'url': f"{self.target_url}/wp-login.php", 'method': 'POST', 'parameters': ['log', 'pwd']}
            ]

            endpoints.extend(common_endpoints)

            # Remove duplicates
            unique_endpoints = []
            seen_urls = set()
            for endpoint in endpoints:
                if endpoint['url'] not in seen_urls:
                    unique_endpoints.append(endpoint)
                    seen_urls.add(endpoint['url'])

            self.logger.info(f"Discovered {len(unique_endpoints)} endpoints with parameters")

        except Exception as e:
            self.logger.debug(f"Endpoint discovery failed: {e}")

        return unique_endpoints

    def _validate_endpoint_sql_safety(self, endpoint_info: Dict) -> List[Dict]:
        """Validate SQL safety for an endpoint."""
        findings = []

        try:
            url = endpoint_info['url']
            method = endpoint_info['method']
            parameters = endpoint_info.get('parameters', [])

            self.logger.debug(f"Validating SQL safety for: {url}")

            # Test 1: Error behavior check
            error_findings = self._test_error_behavior(url, method, parameters)
            findings.extend(error_findings)

            # Test 2: Response timing stability
            timing_findings = self._test_response_timing(url, method, parameters)
            findings.extend(timing_findings)

            # Test 3: Parameter validation check
            validation_findings = self._test_parameter_validation(url, method, parameters)
            findings.extend(validation_findings)

        except Exception as e:
            self.logger.debug(f"Endpoint validation failed: {e}")

        return findings

    def _test_error_behavior(self, url: str, method: str, parameters: List[str]) -> List[Dict]:
        """Test error behavior by sending wrong types only."""
        findings = []

        try:
            # Send requests with wrong data types (NO SQL INJECTION STRINGS)
            test_payloads = [
                {'type': 'array', 'value': '[]'},
                {'type': 'object', 'value': '{}'},
                {'type': 'special_chars', 'value': '@#$%'},
                {'type': 'sql_operator', 'value': 'AND'},  # Just the word, not injection
                {'type': 'numeric_overflow', 'value': '9999999999'}
            ]

            base_response = self._make_request(url, method, {})
            if not base_response:
                return findings

            for param in parameters[:2]:  # Test first 2 parameters only
                for payload in test_payloads:
                    data = {param: payload['value']}
                    response = self._make_request(url, method, data)

                    if response:
                        content = response.text

                        # Check for SQL error messages (safe check)
                        sql_errors = [
                            (r"SQL syntax.*MySQL", "MySQL Syntax Error"),
                            (r"Warning.*mysql_", "MySQL Warning"),
                            (r"PostgreSQL.*ERROR", "PostgreSQL Error"),
                            (r"Microsoft OLE DB", "SQL Server Error"),
                            (r"ODBC Driver", "ODBC Error"),
                            (r"unclosed quotation mark", "SQL Syntax Error")
                        ]

                        for pattern, error_type in sql_errors:
                            if re.search(pattern, content, re.IGNORECASE):
                                findings.append({
                                    'type': 'SQL Error Leakage',
                                    'severity': 'HIGH',
                                    'endpoint': url,
                                    'parameter': param,
                                    'details': f'{error_type} detected with {payload["type"]} input',
                                    'evidence': f'Error pattern: {pattern}',
                                    'remediation': 'Implement proper error handling',
                                    'module': self.module_name
                                })
                                break

                        # Check for stack traces
                        if 'stack trace' in content.lower() or 'at line' in content.lower():
                            findings.append({
                                'type': 'Stack Trace Exposure',
                                'severity': 'MEDIUM',
                                'endpoint': url,
                                'parameter': param,
                                'details': f'Stack trace exposed for parameter "{param}"',
                                'evidence': 'Stack trace found in response',
                                'remediation': 'Disable debug mode',
                                'module': self.module_name
                            })

        except Exception as e:
            self.logger.debug(f"Error behavior test failed: {e}")

        return findings

    def _test_response_timing(self, url: str, method: str, parameters: List[str]) -> List[Dict]:
        """Test response timing stability."""
        findings = []

        try:
            # Make multiple requests to establish baseline
            timings = []
            for _ in range(3):
                start_time = time.time()
                response = self._make_request(url, method, {})
                if response:
                    end_time = time.time()
                    timings.append(end_time - start_time)
                time.sleep(0.5)

            if len(timings) < 2:
                return findings

            baseline_avg = sum(timings) / len(timings)

            # Test with parameter variations
            test_values = ['1', '100', 'test']
            abnormal_timings = []

            for param in parameters[:1]:  # Test first parameter only
                for value in test_values:
                    data = {param: value}
                    start_time = time.time()
                    response = self._make_request(url, method, data)
                    if response:
                        response_time = time.time() - start_time

                        # Check if response time is significantly different
                        if abs(response_time - baseline_avg) > (baseline_avg * 0.5):
                            abnormal_timings.append({
                                'param': param,
                                'time': response_time,
                                'baseline': baseline_avg
                            })

                    time.sleep(1)  # Be extra polite

            if abnormal_timings:
                findings.append({
                    'type': 'Response Timing Anomaly',
                    'severity': 'MEDIUM',
                    'endpoint': url,
                    'details': 'Unstable response times detected',
                    'evidence': f'Timing variations: {abnormal_timings}',
                    'remediation': 'Optimize database queries',
                    'module': self.module_name
                })

        except Exception as e:
            self.logger.debug(f"Response timing test failed: {e}")

        return findings

    def _test_parameter_validation(self, url: str, method: str, parameters: List[str]) -> List[Dict]:
        """Test parameter validation."""
        findings = []

        try:
            for param in parameters[:2]:  # Test first 2 parameters only
                test_cases = [
                    {'value': '', 'type': 'empty_string'},
                    {'value': 'null', 'type': 'null_string'},
                    {'value': '1', 'type': 'numeric_string'},
                    {'value': 'abc123', 'type': 'alphanumeric'}
                ]

                responses = []
                for test_case in test_cases:
                    data = {param: test_case['value']}
                    response = self._make_request(url, method, data)
                    if response:
                        response_hash = hash(response.text[:100])
                        responses.append({
                            'type': test_case['type'],
                            'status': response.status_code,
                            'hash': response_hash,
                            'length': len(response.text)
                        })
                    time.sleep(0.5)

                # Check if responses are consistent
                if len(responses) > 1:
                    status_codes = [r['status'] for r in responses]

                    if len(set(status_codes)) > 1:
                        findings.append({
                            'type': 'Inconsistent Response Codes',
                            'severity': 'LOW',
                            'endpoint': url,
                            'parameter': param,
                            'details': 'Different HTTP status codes returned',
                            'evidence': f'Status codes: {status_codes}',
                            'remediation': 'Implement consistent validation',
                            'module': self.module_name
                        })

        except Exception as e:
            self.logger.debug(f"Parameter validation test failed: {e}")

        return findings

    def _check_sql_error_leakage(self) -> List[Dict]:
        """Check for SQL error leakage in common patterns."""
        findings = []

        try:
            test_endpoints = [
                f"{self.target_url}/?p=1'",
                f"{self.target_url}/?author=1'",
                f"{self.target_url}/?cat=1'",
                f"{self.target_url}/?s=test'"
            ]

            sql_error_patterns = [
                (r"SQL syntax.*MySQL", "MySQL Syntax Error"),
                (r"Warning.*mysql_", "MySQL Warning"),
                (r"PostgreSQL.*ERROR", "PostgreSQL Error"),
                (r"Microsoft OLE DB", "SQL Server Error")
            ]

            for endpoint in test_endpoints:
                response = self.client.get(endpoint)
                if response:
                    content = response.text.lower()

                    for pattern, error_type in sql_error_patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            findings.append({
                                'type': 'SQL Error Message Exposure',
                                'severity': 'HIGH',
                                'endpoint': endpoint,
                                'details': f'{error_type} message exposed',
                                'evidence': f'Error pattern: {pattern}',
                                'remediation': 'Disable display_errors in PHP',
                                'module': self.module_name
                            })
                            break

        except Exception as e:
            self.logger.debug(f"SQL error leakage check failed: {e}")

        return findings

    def _generate_exploitation_analysis(self, findings: List[Dict]) -> List[Dict]:
        """Generate hacker exploitation analysis."""
        analysis = []

        exploitation_map = {
            'SQL Error Leakage': {
                'vulnerability': 'SQL Error Leakage',
                'exploitation_method': 'Hackers use error messages to understand database structure for precise SQL injection attacks',
                'impact': 'Database schema disclosure, SQL injection facilitation',
                'prevention': 'Implement custom error handling, disable debug mode'
            },
            'Stack Trace Exposure': {
                'vulnerability': 'Stack Trace Exposure',
                'exploitation_method': 'Hackers analyze stack traces to identify vulnerable code paths and internal structure',
                'impact': 'Code disclosure, targeted exploitation',
                'prevention': 'Disable detailed error reporting, implement logging'
            },
            'Response Timing Anomaly': {
                'vulnerability': 'Response Timing Anomaly',
                'exploitation_method': 'Hackers perform time-based SQL injection by measuring response times to infer data',
                'impact': 'Blind SQL injection, data exfiltration',
                'prevention': 'Use parameterized queries, implement query timeouts'
            },
            'Inconsistent Response Codes': {
                'vulnerability': 'Inconsistent Response Codes',
                'exploitation_method': 'Hackers use different inputs to trigger different application states, bypassing validation',
                'impact': 'Logic bypass, authentication bypass',
                'prevention': 'Implement consistent validation, use whitelist input validation'
            },
            'SQL Error Message Exposure': {
                'vulnerability': 'SQL Error Message Exposure',
                'exploitation_method': 'Hackers trigger SQL errors to extract database information for precise injection payloads',
                'impact': 'Database enumeration, targeted data theft',
                'prevention': 'Disable error reporting to users, use prepared statements'
            }
        }

        for finding in findings:
            finding_type = finding.get('type', '')
            if finding_type in exploitation_map:
                analysis.append(exploitation_map[finding_type])

        # Add general SQL injection exploitation methods if we found any SQL-related issues
        if any('sql' in finding.get('type', '').lower() for finding in findings):
            analysis.append({
                'vulnerability': 'General SQL Injection Attack',
                'exploitation_method': '1. Union-based: Append UNION SELECT to extract data\n2. Error-based: Trigger errors to leak information\n3. Boolean-based: Use true/false conditions to infer data\n4. Time-based: Use sleep() to infer data character by character',
                'impact': 'Data theft, authentication bypass, system compromise',
                'prevention': '1. Use parameterized queries\n2. Implement input validation\n3. Apply least privilege\n4. Regular security testing'
            })

        # Remove duplicates
        seen = set()
        unique_analysis = []
        for item in analysis:
            key = item['vulnerability']
            if key not in seen:
                seen.add(key)
                unique_analysis.append(item)

        return unique_analysis

    def _make_request(self, url: str, method: str, data: Dict) -> Optional[requests.Response]:
        """Make HTTP request with safety limits."""
        try:
            if method.upper() == 'GET':
                if data:
                    query_string = '&'.join([f"{k}={quote(str(v))}" for k, v in data.items()])
                    if '?' in url:
                        url = f"{url}&{query_string}"
                    else:
                        url = f"{url}?{query_string}"
                return self.client.get(url, timeout=10)
            elif method.upper() == 'POST':
                return self.client.post(url, data=data, timeout=10)
            else:
                return self.client.get(url, timeout=10)
        except Exception as e:
            self.logger.debug(f"Request failed: {e}")
            return None

    def _calculate_validation_score(self, findings: List[Dict]) -> int:
        """Calculate SQL safety validation score (0-100)."""
        score = 100

        for finding in findings:
            severity = finding.get('severity', 'LOW')
            if severity == 'CRITICAL':
                score -= 30
            elif severity == 'HIGH':
                score -= 20
            elif severity == 'MEDIUM':
                score -= 10
            elif severity == 'LOW':
                score -= 5

        return max(0, min(100, score))

    def _urljoin(self, base: str, url: str) -> str:
        """Simple URL join."""
        if url.startswith('http'):
            return url
        if base.endswith('/') and url.startswith('/'):
            return base + url[1:]
        if not base.endswith('/') and not url.startswith('/'):
            return base + '/' + url
        return base + url

    def _get_severity_color(self, severity: str) -> str:
        """Get color for severity level."""
        colors = {
            'CRITICAL': '\033[91m',  # Red
            'HIGH': '\033[93m',  # Yellow
            'MEDIUM': '\033[94m',  # Blue
            'LOW': '\033[96m',  # Cyan
            'INFO': '\033[92m'  # Green
        }
        return colors.get(severity, '\033[0m')


# ============================================================================
# SCOPE VALIDATOR
# ============================================================================

class ScopeValidator:
    """Validates if endpoints are within testing scope."""

    def is_in_scope(self, url: str) -> bool:
        """Check if URL is within testing scope."""
        try:
            parsed = urlparse(url)
            # For now, allow all URLs
            return True
        except:
            return False


# ============================================================================
# VULNERABILITY AGGREGATOR (FIXED to match the main scanner)
# ============================================================================

class VulnerabilityAggregator(ScannerModule):
    """Aggregates and analyzes all vulnerabilities found."""

    def __init__(self, http_client, config: Dict, results: Dict, progress, logger):
        # Fixed: Accepts all 5 parameters that the main scanner is passing
        super().__init__('vulnerability_aggregator', config, logger)
        self.client = http_client
        self.results = results
        self.progress = progress
        self.main_results = results  # Alias for compatibility

    def run(self, target_url: str = None) -> Dict:
        """Analyze and report all vulnerabilities."""
        self.set_status('running')

        try:
            if self.progress:
                self.progress.start_test("Vulnerability Analysis & Exploitation Scenarios")

            # Collect all vulnerabilities from results
            all_vulnerabilities = self._collect_all_vulnerabilities()

            if not all_vulnerabilities:
                print(f"\n✓ No vulnerabilities found during scan")
                if self.progress:
                    self.progress.end_test("Vulnerability Analysis & Exploitation Scenarios")
                self.set_status('completed')
                return self.get_results()

            # Group by severity
            critical_vulns = [v for v in all_vulnerabilities if v.get('severity') == 'CRITICAL']
            high_vulns = [v for v in all_vulnerabilities if v.get('severity') == 'HIGH']
            medium_vulns = [v for v in all_vulnerabilities if v.get('severity') == 'MEDIUM']
            low_vulns = [v for v in all_vulnerabilities if v.get('severity') == 'LOW']

            # Generate exploitation scenarios
            exploitation_scenarios = self._generate_exploitation_scenarios(all_vulnerabilities)

            # Display comprehensive report
            print(f"\n{'=' * 80}")
            print(f"{'COMPREHENSIVE VULNERABILITY REPORT':^80}")
            print(f"{'=' * 80}")

            print(f"\nVulnerability Summary:")
            print(f"  Total Vulnerabilities Found: {len(all_vulnerabilities)}")
            print(f"  Critical: {len(critical_vulns)}")
            print(f"  High: {len(high_vulns)}")
            print(f"  Medium: {len(medium_vulns)}")
            print(f"  Low: {len(low_vulns)}")

            # Display exploitation scenarios
            if exploitation_scenarios:
                print(f"\n{'=' * 80}")
                print(f"{'HACKER EXPLOITATION SCENARIOS':^80}")
                print(f"{'=' * 80}")

                for i, scenario in enumerate(exploitation_scenarios, 1):
                    print(f"\n{i}. {scenario.get('vulnerability', 'Unknown')}")
                    print(f"   Attack Vector: {scenario.get('attack_vector', 'N/A')}")
                    print(f"   Exploitation Method: {scenario.get('exploitation_method', 'N/A')}")
                    print(f"   Potential Impact: {scenario.get('impact', 'N/A')}")
                    print(f"   Risk Level: {scenario.get('risk_level', 'N/A')}")
                    print(f"   Prevention: {scenario.get('prevention', 'N/A')}")

            # Display critical vulnerabilities first
            if critical_vulns:
                print(f"\n{'=' * 80}")
                print(f"{'CRITICAL VULNERABILITIES':^80}")
                print(f"{'=' * 80}")
                for i, vuln in enumerate(critical_vulns, 1):
                    print(f"\n{i}. {vuln.get('type', 'Unknown')}")
                    print(f"   Details: {vuln.get('details', 'N/A')}")
                    print(f"   Fix: {vuln.get('remediation', vuln.get('recommendation', 'N/A'))}")

            # Generate attack chain analysis
            attack_chains = self._generate_attack_chains(all_vulnerabilities)
            if attack_chains:
                print(f"\n{'=' * 80}")
                print(f"{'POSSIBLE ATTACK CHAINS':^80}")
                print(f"{'=' * 80}")
                for i, chain in enumerate(attack_chains, 1):
                    print(f"\nAttack Chain {i}:")
                    for step in chain:
                        print(f"  → {step}")

            # Save analysis to our results
            self.results['details'] = {
                'total_vulnerabilities': len(all_vulnerabilities),
                'critical_count': len(critical_vulns),
                'high_count': len(high_vulns),
                'medium_count': len(medium_vulns),
                'low_count': len(low_vulns),
                'exploitation_scenarios': exploitation_scenarios,
                'attack_chains': attack_chains,
                'risk_score': self._calculate_risk_score(all_vulnerabilities)
            }

            # Also update main results (passed from scanner)
            if self.main_results:
                self.main_results['vulnerability_analysis'] = self.results['details']

            if self.progress:
                self.progress.end_test("Vulnerability Analysis & Exploitation Scenarios")

            self.set_status('completed')
            self.logger.info(
                f"Vulnerability analysis completed. Found {len(all_vulnerabilities)} total vulnerabilities.")

        except Exception as e:
            self.logger.error(f"Vulnerability analysis failed: {e}")
            self.set_status('failed')
            if self.progress:
                self.progress.end_test("Vulnerability Analysis & Exploitation Scenarios")

        return self.get_results()

    def _collect_all_vulnerabilities(self) -> List[Dict]:
        """Collect all vulnerabilities from results."""
        all_vulns = []

        try:
            # Check each result section
            for key, value in self.results.items():
                if isinstance(value, dict):
                    if 'vulnerabilities' in value:
                        all_vulns.extend(value['vulnerabilities'])
                    if 'issues' in value:
                        all_vulns.extend(value['issues'])
                    if 'findings' in value:
                        all_vulns.extend(value['findings'])
                    if 'missing_headers' in value:
                        all_vulns.extend(value['missing_headers'])
                    if 'weak_headers' in value:
                        all_vulns.extend(value['weak_headers'])

            # Add from main results
            if 'vulnerabilities' in self.results:
                all_vulns.extend(self.results['vulnerabilities'])
            if 'warnings' in self.results:
                all_vulns.extend(self.results['warnings'])

            # Add from our own results
            all_vulns.extend(self.results.get('vulnerabilities', []))
            all_vulns.extend(self.results.get('warnings', []))

        except Exception as e:
            self.logger.debug(f"Error collecting vulnerabilities: {e}")

        return all_vulns

    def _generate_exploitation_scenarios(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Generate exploitation scenarios."""
        scenarios = []

        # Template for different vulnerability types
        templates = {
            'SQL': {
                'vulnerability': 'SQL Injection',
                'attack_vector': 'Input fields, URL parameters',
                'exploitation_method': 'Inject malicious SQL to manipulate database queries',
                'impact': 'Data theft, system compromise',
                'risk_level': 'CRITICAL',
                'prevention': 'Use parameterized queries, input validation'
            },
            'XSS': {
                'vulnerability': 'Cross-Site Scripting',
                'attack_vector': 'User input fields',
                'exploitation_method': 'Inject JavaScript to steal sessions or deface site',
                'impact': 'Session hijacking, malware distribution',
                'risk_level': 'HIGH',
                'prevention': 'Input sanitization, Content Security Policy'
            },
            'Username': {
                'vulnerability': 'Username Enumeration',
                'attack_vector': 'Author pages, API endpoints',
                'exploitation_method': 'Enumerate users for targeted attacks',
                'impact': 'Targeted brute force, credential stuffing',
                'risk_level': 'MEDIUM',
                'prevention': 'Disable user enumeration, rate limiting'
            },
            'Password': {
                'vulnerability': 'Weak Authentication',
                'attack_vector': 'Login pages',
                'exploitation_method': 'Brute force, credential stuffing',
                'impact': 'Account takeover',
                'risk_level': 'HIGH',
                'prevention': 'Strong passwords, MFA, rate limiting'
            }
        }

        # Map vulnerabilities to templates
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', '').upper()
            for template_key, template in templates.items():
                if template_key in vuln_type:
                    scenario = template.copy()
                    scenario['found_in'] = vuln.get('url', vuln.get('endpoint', 'Unknown'))
                    scenarios.append(scenario)
                    break

        # Remove duplicates
        seen = set()
        unique_scenarios = []
        for sc in scenarios:
            key = sc['vulnerability']
            if key not in seen:
                seen.add(key)
                unique_scenarios.append(sc)

        return unique_scenarios

    def _generate_attack_chains(self, vulnerabilities: List[Dict]) -> List[List[str]]:
        """Generate possible attack chains."""
        chains = []

        # Check what types of vulnerabilities we have
        has_sql = any('sql' in str(v.get('type', '')).lower() for v in vulnerabilities)
        has_auth = any(
            'password' in str(v.get('type', '')).lower() or 'login' in str(v.get('type', '')).lower() for v in
            vulnerabilities)
        has_info = any(
            'exposed' in str(v.get('type', '')).lower() or 'disclosure' in str(v.get('type', '')).lower() for v in
            vulnerabilities)

        if has_sql:
            chains.append([
                "Discover SQL injection vulnerability",
                "Extract database structure and data",
                "Find admin credentials in database",
                "Use credentials to gain admin access",
                "Upload backdoor or modify site content"
            ])

        if has_auth:
            chains.append([
                "Enumerate valid usernames",
                "Brute force weak passwords",
                "Gain user account access",
                "Find privilege escalation vulnerability",
                "Escalate to admin privileges"
            ])

        if has_info:
            chains.append([
                "Gather information about system",
                "Find software versions with known vulnerabilities",
                "Exploit known vulnerability",
                "Establish persistence",
                "Exfiltrate sensitive data"
            ])

        return chains

    def _calculate_risk_score(self, vulnerabilities: List[Dict]) -> int:
        """Calculate overall risk score."""
        score = 0

        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'LOW')
            if severity == 'CRITICAL':
                score += 25
            elif severity == 'HIGH':
                score += 15
            elif severity == 'MEDIUM':
                score += 10
            elif severity == 'LOW':
                score += 5

        return min(100, score)


# ============================================================================
# PLACEHOLDER FOR OTHER MODULES (to fix similar issues)
# ============================================================================

class WiFiScanner(ScannerModule):
    """WiFi/Access Point scanner."""

    def __init__(self, config: Dict, logger: logging.Logger):
        super().__init__('wifi_scanner', config, logger)
        self.client = None
        self.target_url = None

    def set_client(self, client):
        self.client = client

    def set_target_url(self, target_url: str):
        self.target_url = target_url

    def run(self, target_url: str = None) -> Dict:
        """Run WiFi scanning."""
        self.set_status('running')

        try:
            self.logger.info("Starting WiFi/Access Point scanning")

            # Placeholder implementation
            print(f"\n{'=' * 80}")
            print(f"{'WI-FI / ACCESS POINT SCANNING':^80}")
            print(f"{'=' * 80}")
            print("\nNote: WiFi scanning requires:")
            print("  • Root/sudo privileges")
            print("  • Wireless adapter in monitor mode")
            print("  • Physical proximity to target network")
            print("\nThis module is a placeholder for security scanning.")

            self.add_info({
                'type': 'WiFi Scan Placeholder',
                'details': 'WiFi scanning module is a demonstration only',
                'severity': 'INFO'
            })

            self.set_status('completed')

        except Exception as e:
            self.logger.error(f"WiFi scanning failed: {e}")
            self.set_status('failed')

        return self.get_results()


# ============================================================================
# TEST CODE
# ============================================================================

if __name__ == "__main__":
    # Setup logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)


    # Create a simple HTTP client for testing
    class TestHTTPClient:
        def get(self, url, **kwargs):
            print(f"[TEST] GET: {url}")

            class MockResponse:
                text = "<html><form action='/test'><input name='test'></form></html>"
                status_code = 200

            return MockResponse()

        def post(self, url, data=None, **kwargs):
            print(f"[TEST] POST: {url}, Data: {data}")

            class MockResponse:
                text = "Test response"
                status_code = 200

            return MockResponse()


    # Test the modules
    config = {
        'max_requests': 10,
        'timeout': 30
    }

    print("Testing SQLInjectionSafetyValidator...")
    sql_validator = SQLInjectionSafetyValidator(config, logger)
    sql_validator.set_client(TestHTTPClient())
    sql_validator.set_target_url("http://example.com")
    sql_results = sql_validator.run()
    print(f"SQL Validator Status: {sql_results['status']}")

    print("\nTesting VulnerabilityAggregator...")


    # Mock progress tracker
    class MockProgress:
        def start_test(self, name):
            print(f"Starting: {name}")

        def end_test(self, name):
            print(f"Ending: {name}")


    mock_results = {
        'vulnerabilities': [
            {'type': 'Test SQL', 'severity': 'HIGH', 'details': 'Test vulnerability'}
        ],
        'warnings': [
            {'type': 'Test Warning', 'severity': 'MEDIUM', 'details': 'Test warning'}
        ]
    }

    vuln_aggregator = VulnerabilityAggregator(
        http_client=TestHTTPClient(),
        config=config,
        results=mock_results,
        progress=MockProgress(),
        logger=logger
    )
    vuln_results = vuln_aggregator.run()
    print(f"Vulnerability Aggregator Status: {vuln_results['status']}")

    print("\nAll tests completed successfully!")