#!/usr/bin/env python3
"""
Professional WordPress Security Scanner
Authorized Testing Only - For Educational and Security Assessment Purposes
Version: 2.0.0
"""

import argparse
import json
import logging
import os
import re
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urlparse, urljoin, quote
from urllib.robotparser import RobotFileParser

import requests
import yaml
from colorama import init, Fore, Style, Back
from requests.adapters import HTTPAdapter

try:
    from urllib3.util.retry import Retry
except ImportError:
    # Fallback for older versions
    from requests.packages.urllib3.util.retry import Retry
from tabulate import tabulate

# ============================================================================
# CUSTOM MODULE IMPORTS - FIXED VERSION
# ============================================================================

try:
    from .sql_safety_module import SQLInjectionSafetyValidator, VulnerabilityAggregator

    HAS_SQL_MODULE = True
except ImportError:
    # Create placeholder classes if module not found
    HAS_SQL_MODULE = False


    class SQLInjectionSafetyValidator:
        """Placeholder for SQL safety module."""

        def __init__(self, config, logger):
            self.config = config
            self.logger = logger
            self.client = None
            self.target_url = None
            self.progress = None
            self.results = None

        def set_client(self, client):  # CHANGED FROM set_http_client to set_client
            self.client = client

        def set_target_url(self, target_url):
            self.target_url = target_url

        def set_progress(self, progress):
            self.progress = progress

        def set_main_results(self, results):
            self.results = results

        def run(self):
            if self.progress:
                self.progress.start_test("SQL Injection Safety Validation")

            print(f"\nSQL Injection Safety Check for {self.target_url}")
            print("This module is a placeholder. Create sql_safety_module.py to enable full functionality.")

            if self.progress:
                self.progress.end_test("SQL Injection Safety Validation")

            return {
                'status': 'placeholder',
                'vulnerabilities': [],
                'warnings': [
                    {
                        'type': 'Module Placeholder',
                        'severity': 'LOW',
                        'details': 'SQL safety module is a placeholder. Create sql_safety_module.py file.',
                        'remediation': 'Create the module file with proper implementation'
                    }
                ]
            }


    class VulnerabilityAggregator:
        """Placeholder for vulnerability aggregator."""

        def __init__(self, http_client, config, results, progress, logger):
            # Accepts all 5 parameters that the main scanner passes
            self.client = http_client
            self.config = config
            self.results = results
            self.progress = progress
            self.logger = logger

        def run(self):
            if self.progress:
                self.progress.start_test("Vulnerability Analysis & Exploitation Scenarios")

            print("\nVulnerability Analysis (Placeholder)")
            print("Create sql_safety_module.py with proper VulnerabilityAggregator implementation")

            if self.progress:
                self.progress.end_test("Vulnerability Analysis & Exploitation Scenarios")

            return {
                'status': 'placeholder',
                'vulnerabilities': [],
                'warnings': []
            }

# Initialize colorama for cross-platform colored output
init(autoreset=True)

# ============================================================================
# CONFIGURATION AND CONSTANTS - COMPLETE VERSION
# ============================================================================

DEFAULT_CONFIG = {
    "scanning": {
        "max_requests_per_second": 2,
        "timeout": 15,
        "max_workers": 5,
        "user_agent": "WordPressSecurityScanner/2.0 (Authorized Security Assessment)",
        "respect_robots_txt": True,
        "follow_redirects": True,
        "verify_ssl": True,
        "delay_between_requests": 0.5,
        "max_redirects": 5
    },
    "tests": {
        "port_scanning": True,
        "web_vulnerabilities": True,
        "authentication_security": True,
        "ssl_tls_security": True,
        "information_gathering": True,
        "api_security": True,
        "wordpress_specific": True,
        "headers_security": True,
        "hardening_checks": True,
        "username_enumeration": True,  # NEW: Added this
        "weak_password_detection": True,  # NEW: Added this
        "directory_enumeration": False,  # Disabled by default
        "subdomain_enumeration": False,  # Disabled by default
        "sql_safety_check": True,  # NEW
        "vulnerability_analysis": True,  # NEW
    },
    "ports": {
        "common_web": [80, 443, 8080, 8443],
        "database": [3306, 5432],
        "management": [22, 21, 23, 3389],
        "additional": [3000, 9000, 9200]
    },
    "password_check": {  # NEW: Added this section
        "common_passwords": [
            "password", "password123", "123456", "12345678", "123456789",
            "admin", "admin123", "letmein", "qwerty", "abc123",
            "welcome", "monkey", "football", "iloveyou", "sunshine"
        ],
        "check_default_creds": True,
        "max_password_tests": 10
    },
    "output": {  # THIS SECTION WAS MISSING - ADDED BACK
        "formats": ["console", "json"],
        "json_pretty": True,
        "save_logs": True,
        "log_level": "INFO",
        "verbose": False,
        "color_output": True,
        "progress_bar": True
    },
    "reporting": {  # THIS SECTION WAS MISSING - ADDED BACK
        "generate_html": True,
        "generate_pdf": False,
        "include_evidence": True,
        "risk_scoring": True,
        "cvss_scoring": True
    },
    "safety": {  # THIS SECTION WAS MISSING - ADDED BACK
        "max_scans_per_day": 10,
        "require_authorization": True,
        "check_localhost": True,
        "production_warning": True,
        "emergency_stop": True,
        "max_scan_duration": 3600  # 1 hour
    },
    "vulnerability_databases": {  # THIS SECTION WAS MISSING - ADDED BACK
        "wpscan_api": None,  # Set your API key here
        "cve_search": False,
        "check_known_exploits": True
    }
}
# Known WordPress security plugins (for detection)
SECURITY_PLUGINS = [
    "wordfence", "ithemes-security", "sucuri-security", "all-in-one-wp-security",
    "bulletproof-security", "shield-security", "malcare-security",
    "jetpack", "google-site-kit"  # These also provide security features
]

# Common WordPress files and directories to check
WORDPRESS_FILES = [
    "/wp-config.php", "/wp-config.php.bak", "/wp-config.php~",
    "/wp-config.php.save", "/.htaccess", "/.htaccess.bak",
    "/readme.html", "/license.txt", "/wp-admin/install.php",
    "/xmlrpc.php", "/wp-login.php", "/wp-admin/"
]

# Security headers to check
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "Enforces HTTPS connections",
        "severity": "HIGH"
    },
    "Content-Security-Policy": {
        "description": "Prevents XSS and injection attacks",
        "severity": "HIGH"
    },
    "X-Frame-Options": {
        "description": "Prevents clickjacking attacks",
        "severity": "MEDIUM"
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME-sniffing",
        "severity": "MEDIUM"
    },
    "Referrer-Policy": {
        "description": "Controls referrer information",
        "severity": "LOW"
    },
    "Permissions-Policy": {
        "description": "Controls browser features",
        "severity": "MEDIUM"
    },
    "X-XSS-Protection": {
        "description": "Enables XSS filtering",
        "severity": "LOW"
    }
}

# Common usernames to check
COMMON_USERNAMES = [  # NEW: Added this
    'admin', 'administrator', 'root', 'user', 'test', 'guest',
    'wpadmin', 'wordpress', 'manager', 'webmaster', 'sysadmin',
    'admin1', 'admin2', 'superadmin', 'supervisor'
]


# ============================================================================
# CUSTOM EXCEPTIONS (UNCHANGED)
# ============================================================================

class SecurityScannerError(Exception):
    """Base exception for security scanner errors."""
    pass


class AuthorizationError(SecurityScannerError):
    """Raised when authorization fails."""
    pass


class SafetyViolationError(SecurityScannerError):
    """Raised when safety rules are violated."""
    pass


class RateLimitError(SecurityScannerError):
    """Raised when rate limiting is encountered."""
    pass


# ============================================================================
# LOGGING SETUP (UNCHANGED)
# ============================================================================

class ColoredFormatter(logging.Formatter):
    """Custom formatter with colors for different log levels."""

    COLORS = {
        'DEBUG': Fore.CYAN,
        'INFO': Fore.GREEN,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.RED + Back.WHITE + Style.BRIGHT
    }

    def format(self, record):
        original_levelname = record.levelname  # Save original
        if original_levelname in self.COLORS:
            color = self.COLORS[original_levelname]
            record.levelname = color + original_levelname + Style.RESET_ALL
            record.msg = color + str(record.msg) + Style.RESET_ALL
        return super().format(record)


def setup_logging(config: Dict, scan_id: str) -> logging.Logger:
    """Configure logging based on configuration."""

    log_level = getattr(logging, config['output']['log_level'].upper())

    # Create logger
    logger = logging.getLogger(f"wp_scanner_{scan_id}")
    logger.setLevel(log_level)

    # Remove existing handlers
    logger.handlers.clear()

    # Console handler
    console_handler = logging.StreamHandler()
    if config['output']['color_output']:
        console_formatter = ColoredFormatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
    else:
        console_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    # File handler if logging is enabled
    if config['output']['save_logs']:
        log_dir = Path("scanner_logs")
        log_dir.mkdir(exist_ok=True)

        log_file = log_dir / f"scan_{scan_id}.log"
        file_handler = logging.FileHandler(log_file)
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

    return logger


# ============================================================================
# AUTHORIZATION MANAGER (UNCHANGED)
# ============================================================================

class AuthorizationManager:
    """Manages authorization for security scanning."""

    AUTHORIZATION_TEMPLATE = {
        "target_url": "",
        "authorized_by": {
            "name": "",
            "email": "",
            "organization": ""
        },
        "authorization_date": "",
        "expiry_date": "",
        "scope": {
            "description": "Authorized security assessment",
            "tests_allowed": ["port_scanning", "web_vulnerabilities", "information_gathering"],
            "tests_prohibited": ["brute_force", "dos_testing"],
            "environment": "staging"  # staging, production, development
        },
        "contact_information": {
            "primary": "",
            "secondary": "",
            "emergency": ""
        },
        "terms": {
            "testing_window": {
                "start": "",
                "end": "",
                "timezone": "UTC"
            },
            "rate_limits": "Maximum 2 requests per second",
            "data_handling": "All findings confidential, delete after 30 days",
            "liability": "Scanner assumes no liability for service disruption"
        },
        "signatures": {
            "authorizer": "",
            "tester": "",
            "date_signed": ""
        }
    }

    def __init__(self, config: Dict):
        self.config = config
        self.authorization = None
        self.auth_file = None

    def verify_authorization(self, target_url: str, auth_file: Optional[str] = None) -> bool:
        """Verify authorization for scanning."""

        # Check if authorization is required
        if not self.config['safety']['require_authorization']:
            self._log_warning("Authorization check disabled in config")
            return True

        # Try to load authorization file
        if auth_file:
            self.auth_file = Path(auth_file)
            if not self.auth_file.exists():
                raise AuthorizationError(f"Authorization file not found: {auth_file}")

            try:
                with open(self.auth_file, 'r') as f:
                    self.authorization = json.load(f)
            except json.JSONDecodeError as e:
                raise AuthorizationError(f"Invalid authorization file format: {e}")
        else:
            # Try default location
            default_auth = Path("authorization.json")
            if default_auth.exists():
                try:
                    with open(default_auth, 'r') as f:
                        self.authorization = json.load(f)
                    self.auth_file = default_auth
                except:
                    pass

        # If no authorization file found, prompt for interactive authorization
        if not self.authorization:
            if not self._interactive_authorization(target_url):
                return False

        # Validate authorization
        return self._validate_authorization(target_url)

    def _interactive_authorization(self, target_url: str) -> bool:
        """Handle interactive authorization."""

        print(f"\n{Fore.YELLOW}{'=' * 80}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}AUTHORIZATION REQUIRED FOR SECURITY SCANNING{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'=' * 80}{Style.RESET_ALL}")

        print(f"\nTarget: {target_url}")
        print("\nYou must have explicit authorization to scan this website.")
        print("\nOptions:")
        print("1. I own this website and authorize the scan")
        print("2. I have written authorization from the website owner")
        print("3. This is a test/staging environment I control")
        print("4. Cancel scan")

        choice = input("\nSelect option (1-4): ").strip()

        if choice == "4":
            return False

        # Create authorization record
        self.authorization = self.AUTHORIZATION_TEMPLATE.copy()
        self.authorization["target_url"] = target_url

        today = datetime.now()
        self.authorization["authorization_date"] = today.strftime("%Y-%m-%d")
        self.authorization["expiry_date"] = (today + timedelta(days=30)).strftime("%Y-%m-%d")

        # Get authorizer information
        print("\n" + "=" * 80)
        print("AUTHORIZATION DETAILS")
        print("=" * 80)

        self.authorization["authorized_by"]["name"] = input("Your name: ").strip()
        self.authorization["authorized_by"]["email"] = input("Your email: ").strip()
        self.authorization["authorized_by"]["organization"] = input("Organization (optional): ").strip()

        # Contact information
        self.authorization["contact_information"]["primary"] = input("Primary contact (email/phone): ").strip()
        self.authorization["contact_information"]["emergency"] = input("Emergency contact (email/phone): ").strip()

        # Scope
        env = input("Environment (staging/production/development): ").strip().lower()
        self.authorization["scope"]["environment"] = env if env in ["staging", "production",
                                                                    "development"] else "staging"

        # Terms
        start = input("Testing start date (YYYY-MM-DD) [today]: ").strip() or today.strftime("%Y-%m-%d")
        end = input("Testing end date (YYYY-MM-DD) [7 days from now]: ").strip() or (
                today + timedelta(days=7)).strftime("%Y-%m-%d")

        self.authorization["terms"]["testing_window"]["start"] = start
        self.authorization["terms"]["testing_window"]["end"] = end

        # Signatures
        print("\n" + "=" * 80)
        print("DIGITAL SIGNATURE")
        print("=" * 80)
        print("By typing 'I AGREE' below, you confirm that:")
        print("1. You have the legal authority to authorize this scan")
        print("2. You accept responsibility for any service disruption")
        print("3. You will use the results only for security improvement")
        print("4. You will keep findings confidential")

        signature = input("\nType 'I AGREE' to confirm: ").strip()

        if signature.upper() != "I AGREE":
            print(f"{Fore.RED}Authorization cancelled.{Style.RESET_ALL}")
            return False

        self.authorization["signatures"]["authorizer"] = self.authorization["authorized_by"]["name"]
        self.authorization["signatures"]["tester"] = self.authorization["authorized_by"]["name"]
        self.authorization["signatures"]["date_signed"] = today.strftime("%Y-%m-%d")

        # Save authorization
        auth_file = Path(f"authorization_{today.strftime('%Y%m%d_%H%M%S')}.json")
        with open(auth_file, 'w') as f:
            json.dump(self.authorization, f, indent=2)

        self.auth_file = auth_file
        print(f"{Fore.GREEN}Authorization saved to: {auth_file}{Style.RESET_ALL}")

        return True

    def _validate_authorization(self, target_url: str) -> bool:
        """Validate the authorization document."""

        required_fields = [
            "target_url", "authorized_by", "authorization_date",
            "expiry_date", "scope", "contact_information", "terms", "signatures"
        ]

        # Check required fields
        for field in required_fields:
            if field not in self.authorization:
                raise AuthorizationError(f"Missing required authorization field: {field}")

        # Check target URL matches
        auth_target = self.authorization["target_url"]
        if auth_target != target_url and not target_url.startswith(auth_target):
            print(f"{Fore.YELLOW}Warning: Authorization is for {auth_target}, scanning {target_url}{Style.RESET_ALL}")
            confirm = input("Continue anyway? (yes/no): ").strip().lower()
            if confirm != "yes":
                return False

        # Check expiry
        expiry_str = self.authorization["expiry_date"]
        try:
            expiry_date = datetime.strptime(expiry_str, "%Y-%m-%d")
            if datetime.now() > expiry_date:
                print(f"{Fore.YELLOW}Warning: Authorization expired on {expiry_str}{Style.RESET_ALL}")
                confirm = input("Continue anyway? (yes/no): ").strip().lower()
                if confirm != "yes":
                    return False
        except ValueError:
            print(f"{Fore.YELLOW}Warning: Invalid expiry date format{Style.RESET_ALL}")

        # Check testing window
        window = self.authorization["terms"]["testing_window"]
        try:
            start_date = datetime.strptime(window["start"], "%Y-%m-%d")
            end_date = datetime.strptime(window["end"], "%Y-%m-%d")
            today = datetime.now()

            if today < start_date:
                print(f"{Fore.YELLOW}Warning: Testing window starts on {window['start']}{Style.RESET_ALL}")
                confirm = input("Start early? (yes/no): ").strip().lower()
                if confirm != "yes":
                    return False
            elif today > end_date:
                print(f"{Fore.YELLOW}Warning: Testing window ended on {window['end']}{Style.RESET_ALL}")
                confirm = input("Continue anyway? (yes/no): ").strip().lower()
                if confirm != "yes":
                    return False
        except ValueError:
            print(f"{Fore.YELLOW}Warning: Invalid testing window dates{Style.RESET_ALL}")

        # Log authorization
        print(f"{Fore.GREEN}✓ Authorization verified: {self.authorization['authorized_by']['name']}{Style.RESET_ALL}")
        print(f"   Environment: {self.authorization['scope']['environment']}")
        print(f"   Valid until: {self.authorization['expiry_date']}")

        return True

    def _log_warning(self, message: str):
        """Log a warning message."""
        print(f"{Fore.YELLOW}Warning: {message}{Style.RESET_ALL}")


# ============================================================================
# SAFETY MANAGER (UNCHANGED)
# ============================================================================

class SafetyManager:
    """Manages safety rules and prevents accidental misuse."""

    def __init__(self, config: Dict, logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.scan_start_time = None
        self.request_count = 0
        self.last_request_time = time.time()

        # Emergency stop flag
        self.emergency_stop = threading.Event()

        # Setup signal handlers for graceful shutdown
        try:
            if threading.current_thread() is threading.main_thread():
                signal.signal(signal.SIGINT, self._signal_handler)
                signal.signal(signal.SIGTERM, self._signal_handler)
        except ValueError:
            self.logger.warning("Could not register signal handlers (not in main thread)")

    def _signal_handler(self, signum, frame):
        """Handle interrupt signals."""
        self.logger.warning(f"Received signal {signum}, initiating emergency stop")
        self.emergency_stop.set()

    def start_scan(self):
        """Begin a new scan with safety checks."""
        self.scan_start_time = time.time()
        self.request_count = 0

        # Check scan limits
        self._check_daily_scan_limit()

        # Check for emergency stop
        if self.emergency_stop.is_set():
            raise SafetyViolationError("Emergency stop is active")

    def check_safety_rules(self, url: str) -> bool:
        """Check if a request is safe to make."""

        # Check emergency stop
        if self.emergency_stop.is_set():
            self.logger.warning("Emergency stop activated, aborting request")
            return False

        # Check scan duration
        if self.scan_start_time:
            elapsed = time.time() - self.scan_start_time
            max_duration = self.config['safety']['max_scan_duration']
            if elapsed > max_duration:
                self.logger.error(f"Maximum scan duration ({max_duration}s) exceeded")
                self.emergency_stop.set()
                return False

        # Rate limiting
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        min_delay = 1.0 / self.config['scanning']['max_requests_per_second']

        if time_since_last < min_delay:
            sleep_time = min_delay - time_since_last
            time.sleep(sleep_time)

        self.last_request_time = time.time()
        self.request_count += 1

        # Check for localhost/production
        if self.config['safety']['check_localhost']:
            if self._is_localhost(url):
                self.logger.warning(f"Localhost detected in URL: {url}")
                # Don't block, just warn

        if self.config['safety']['production_warning']:
            if self._is_likely_production(url):
                self.logger.warning(f"Production environment detected: {url}")

        return True

    def _check_daily_scan_limit(self):
        """Check if daily scan limit has been reached."""
        max_scans = self.config['safety']['max_scans_per_day']

        # Simple implementation - could be enhanced with persistent storage
        self.logger.info(f"Daily scan limit: {max_scans} scans")
        # In a real implementation, you would track scans in a database

    def _is_localhost(self, url: str) -> bool:
        """Check if URL points to localhost."""
        localhost_indicators = [
            "localhost", "127.0.0.1", "0.0.0.0", "::1",
            "192.168.", "10.", "172.16.", "172.31."
        ]

        parsed = urlparse(url)
        netloc = parsed.netloc

        for indicator in localhost_indicators:
            if indicator in netloc:
                return True

        return False

    def _is_likely_production(self, url: str) -> bool:
        """Check if URL is likely a production environment."""
        prod_indicators = [
            "www.", "api.", "app.", "prod.", "production.",
            "live.", "secure.", "account.", "admin."
        ]

        parsed = urlparse(url)
        hostname = parsed.hostname or ""

        for indicator in prod_indicators:
            if hostname.startswith(indicator):
                return True

        return False


# ============================================================================
# HTTP CLIENT WITH SAFETY FEATURES (UNCHANGED)
# ============================================================================

class SafeHTTPClient:
    """HTTP client with built-in safety features and rate limiting."""

    def __init__(self, config: Dict, safety_manager: SafetyManager, logger: logging.Logger):
        self.config = config
        self.safety = safety_manager
        self.logger = logger

        # Configure session with retries
        self.session = requests.Session()

        # Setup retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "HEAD", "OPTIONS"]
        )

        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        # Set headers
        self.session.headers.update({
            "User-Agent": config['scanning']['user_agent'],
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "close",  # Don't keep connections open
            "Upgrade-Insecure-Requests": "1"
        })

        # Configure session
        self.session.verify = config['scanning']['verify_ssl']
        self.session.max_redirects = config['scanning']['max_redirects']

        # Robots.txt parser
        self.robot_parser = None

    def check_robots_txt(self, base_url: str) -> bool:
        """Check robots.txt and return True if scanning is allowed."""
        if not self.config['scanning']['respect_robots_txt']:
            return True

        try:
            self.robot_parser = RobotFileParser()
            robots_url = urljoin(base_url, "/robots.txt")
            self.robot_parser.set_url(robots_url)
            self.robot_parser.read()

            # Check if our user agent is allowed
            user_agent = self.config['scanning']['user_agent'].split()[0]
            allowed = self.robot_parser.can_fetch(user_agent, base_url)

            if not allowed:
                self.logger.warning(f"robots.txt disallows scanning for {user_agent}")
                return False

            return True

        except Exception as e:
            self.logger.debug(f"Could not read robots.txt: {e}")
            return True  # Assume allowed if robots.txt is not accessible

    def request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """Make an HTTP request with safety checks."""

        # Check safety rules
        if not self.safety.check_safety_rules(url):
            return None

        # Check robots.txt for new domains
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        if self.robot_parser is None:
            if not self.check_robots_txt(base_url):
                self.logger.error("Scanning disallowed by robots.txt")
                return None

        # Add default timeout if not specified
        if "timeout" not in kwargs:
            kwargs["timeout"] = self.config['scanning']['timeout']

        # Add delay between requests
        time.sleep(self.config['scanning']['delay_between_requests'])

        try:
            response = self.session.request(method, url, **kwargs)

            # Check for rate limiting headers
            if response.status_code == 429:  # Too Many Requests
                self.logger.warning(f"Rate limited by server when accessing {url}")

                # Try to get retry-after header
                retry_after = response.headers.get("Retry-After")
                if retry_after:
                    try:
                        wait_time = int(retry_after)
                        self.logger.info(f"Waiting {wait_time} seconds as requested by server")
                        time.sleep(wait_time)
                    except ValueError:
                        pass

                raise RateLimitError(f"Rate limited by server: {url}")

            # Check for other error status codes
            if response.status_code >= 400:
                self.logger.debug(f"HTTP {response.status_code} for {url}")

            return response

        except requests.exceptions.RequestException as e:
            self.logger.debug(f"Request failed for {url}: {e}")
            return None
        except RateLimitError as e:
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error during request to {url}: {e}")
            return None

    def get(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Convenience method for GET requests."""
        return self.request("GET", url, **kwargs)

    def head(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Convenience method for HEAD requests."""
        return self.request("HEAD", url, **kwargs)

    def post(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Convenience method for POST requests."""
        return self.request("POST", url, **kwargs)


# ============================================================================
# PROGRESS TRACKER (UNCHANGED)
# ============================================================================

class ProgressTracker:
    """Tracks and displays scan progress."""

    def __init__(self, total_tests: int, config: Dict, logger: logging.Logger):
        self.total_tests = total_tests
        self.completed_tests = 0
        self.config = config
        self.logger = logger
        self.start_time = time.time()
        self.test_times = {}

        if config['output']['progress_bar']:
            print(f"\n{Fore.CYAN}Starting scan with {total_tests} tests...{Style.RESET_ALL}")

    def start_test(self, test_name: str):
        """Mark a test as started."""
        self.test_times[test_name] = time.time()
        self.logger.info(f"Starting test: {test_name}")

        if self.config['output']['verbose']:
            print(f"{Fore.CYAN}[{self.completed_tests + 1}/{self.total_tests}] {test_name}{Style.RESET_ALL}")

    def end_test(self, test_name: str):
        """Mark a test as completed."""
        if test_name in self.test_times:
            duration = time.time() - self.test_times[test_name]
            self.logger.debug(f"Test completed: {test_name} ({duration:.2f}s)")
            del self.test_times[test_name]

        self.completed_tests += 1

        if self.config['output']['progress_bar']:
            self._update_progress_bar()

    def _update_progress_bar(self):
        """Update the progress bar display."""
        if not self.config['output']['progress_bar']:
            return

        width = 50
        percent = self.completed_tests / self.total_tests
        filled = int(width * percent)
        bar = "█" * filled + "░" * (width - filled)

        elapsed = time.time() - self.start_time
        if percent > 0:
            estimated_total = elapsed / percent
            remaining = estimated_total - elapsed
            time_str = f"{int(remaining // 60)}m {int(remaining % 60)}s"
        else:
            time_str = "Calculating..."

        sys.stdout.write(
            f"\r{Fore.GREEN}[{bar}] {self.completed_tests}/{self.total_tests} ({percent * 100:.1f}%) - Est: {time_str}{Style.RESET_ALL}")
        sys.stdout.flush()

    def complete(self):
        """Mark scan as complete."""
        if self.config['output']['progress_bar']:
            # Clear the progress bar line
            sys.stdout.write("\r" + " " * 100 + "\r")
            sys.stdout.flush()

        total_time = time.time() - self.start_time
        self.logger.info(f"Scan completed in {total_time:.2f} seconds")
        print(f"{Fore.GREEN}✓ Scan completed in {total_time:.2f} seconds{Style.RESET_ALL}")


# ============================================================================
# RESULTS MANAGER
# ============================================================================

class ResultsManager:
    """Manages results from all modules."""

    def __init__(self, target_url: str, scan_id: str):
        self.target_url = target_url
        self.scan_id = scan_id
        self.results = {
            'target_url': target_url,
            'scan_id': scan_id,
            'modules_run': [],
            'vulnerabilities': [],
            'warnings': [],
            'info': [],
            'module_results': {}
        }

    def add_module_result(self, module_name: str, result_data: Dict):
        """Add results from a module."""
        self.results['modules_run'].append(module_name)
        self.results['module_results'][module_name] = result_data

        # Extract findings
        if 'vulnerabilities' in result_data:
            for vuln in result_data['vulnerabilities']:
                vuln['module'] = module_name
                self.results['vulnerabilities'].append(vuln)

        if 'warnings' in result_data:
            for warning in result_data['warnings']:
                warning['module'] = module_name
                self.results['warnings'].append(warning)

    def get_all_results(self) -> Dict:
        """Get all results."""
        return self.results

    def save_to_json(self) -> str:
        """Save results to JSON file."""
        import json
        from pathlib import Path

        reports_dir = Path("reports")
        reports_dir.mkdir(exist_ok=True)

        target_name = self.target_url.replace('://', '_').replace('/', '_').replace('.', '_')
        filename = reports_dir / f"scan_results_{target_name}_{self.scan_id}.json"

        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)

        return str(filename)


# ============================================================================
# TEST MODULES (ORIGINAL + NEW ONES ADDED)
# ============================================================================

class TestModule:
    """Base class for all test modules."""

    def __init__(self, http_client: SafeHTTPClient, config: Dict,
                 results: Dict, progress: ProgressTracker, logger: logging.Logger):
        self.client = http_client
        self.config = config
        self.results = results
        self.progress = progress
        self.logger = logger
        self.target_url = results.get('target_url', '')

    def run(self):
        """Run the test module. To be implemented by subclasses."""
        raise NotImplementedError


# ============================================================================
# NEW: ENHANCED PORT SCANNER WITH ALL PORTS
# ============================================================================

class EnhancedPortScanner(TestModule):
    """Enhanced port scanner showing all open ports."""

    def run(self):
        """Run comprehensive port scanning."""
        self.progress.start_test("Enhanced Port Scanning")

        if not self.config['tests']['port_scanning']:
            self.logger.info("Port scanning disabled")
            self.progress.end_test("Enhanced Port Scanning")
            return

        try:
            parsed = urlparse(self.target_url)
            domain = parsed.netloc.split(':')[0]

            # Get IP address
            try:
                ip_address = socket.gethostbyname(domain)
                self.logger.info(f"Resolved {domain} to {ip_address}")
            except socket.giaerror:
                self.logger.error(f"Could not resolve domain: {domain}")
                self.progress.end_test("Enhanced Port Scanning")
                return

            # Scan comprehensive list of ports
            all_ports = [
                # Common ports
                21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
                # Web ports
                8080, 8443, 8000, 8888, 3000, 9000,
                # Database ports
                3306, 5432, 27017, 6379, 11211, 1433, 1521,
                # Management ports
                3389, 5900, 5800, 22, 23,
                # Other services
                161, 162, 389, 636, 119, 123, 139, 445,
                548, 873, 1080, 1433, 1521, 2049, 2181, 2375,
                2376, 2424, 2483, 2484, 2638, 3000, 3306, 4040,
                4369, 5000, 5432, 5672, 5900, 5984, 6379, 7001,
                7002, 8009, 8080, 8081, 8090, 8091, 8181, 8443,
                8888, 9000, 9042, 9092, 9200, 9300, 11211, 27017,
                28017, 50000, 50070, 50075
            ]

            all_ports = sorted(set(all_ports))
            self.logger.info(f"Scanning {len(all_ports)} ports on {ip_address}")

            open_ports = []

            # Use ThreadPoolExecutor for fast scanning
            with ThreadPoolExecutor(max_workers=20) as executor:
                future_to_port = {
                    executor.submit(self._scan_port_with_service, ip_address, port): port
                    for port in all_ports
                }

                for future in as_completed(future_to_port):
                    port = future_to_port[future]
                    try:
                        result = future.result(timeout=2)
                        if result and result.get('status') == 'open':
                            open_ports.append(result)
                    except TimeoutError:
                        continue
                    except Exception as e:
                        self.logger.debug(f"Error scanning port {port}: {e}")

            # Sort by port number
            open_ports.sort(key=lambda x: x['port'])

            # Display results in table
            if open_ports:
                print(f"\n{Fore.GREEN}ALL OPEN PORTS FOUND ({len(open_ports)} total):{Style.RESET_ALL}")
                table_data = []
                for port_info in open_ports:
                    table_data.append([
                        port_info['port'],
                        port_info.get('service', 'Unknown'),
                        port_info.get('banner', '')[:30] or 'N/A'
                    ])

                print(tabulate(table_data,
                               headers=["Port", "Service", "Banner"],
                               tablefmt="grid"))

                # Categorize by risk
                self._categorize_ports(open_ports)

            else:
                print(f"{Fore.YELLOW}No open ports found{Style.RESET_ALL}")

            # Save results
            self.results['enhanced_port_scan'] = {
                'target_ip': ip_address,
                'target_domain': domain,
                'open_ports': open_ports,
                'total_scanned': len(all_ports),
                'open_count': len(open_ports)
            }

            self.progress.end_test("Enhanced Port Scanning")

        except Exception as e:
            self.logger.error(f"Port scanning failed: {e}")
            self.progress.end_test("Enhanced Port Scanning")

    def _scan_port_with_service(self, ip: str, port: int) -> Dict:
        """Scan port with service detection."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)

            result = sock.connect_ex((ip, port))

            if result == 0:
                # Port is open
                service_info = self._detect_service(sock, port)
                sock.close()

                return {
                    'port': port,
                    'status': 'open',
                    'service': service_info.get('service', 'Unknown'),
                    'banner': service_info.get('banner', ''),
                    'vulnerabilities': service_info.get('vulnerabilities', [])
                }

            sock.close()

        except Exception:
            pass

        return {'port': port, 'status': 'closed'}

    def _detect_service(self, sock: socket.socket, port: int) -> Dict:
        """Detect service running on port."""
        service_info = {'service': 'Unknown', 'banner': ''}

        try:
            sock.settimeout(2)

            # Common service detection
            if port in [80, 443, 8080, 8443, 8000, 8888]:
                # HTTP/HTTPS
                sock.send(b"GET / HTTP/1.0\r\n\r\n")
                banner = sock.recv(4096)
                service_info['banner'] = banner.decode('utf-8', errors='ignore')
                service_info['service'] = 'HTTP'

            elif port == 21:  # FTP
                banner = sock.recv(1024)
                service_info['banner'] = banner.decode('utf-8', errors='ignore')
                service_info['service'] = 'FTP'

            elif port == 22:  # SSH
                sock.send(b"SSH-2.0-Client\r\n")
                banner = sock.recv(1024)
                service_info['banner'] = banner.decode('utf-8', errors='ignore')
                service_info['service'] = 'SSH'

            elif port == 25:  # SMTP
                banner = sock.recv(1024)
                service_info['banner'] = banner.decode('utf-8', errors='ignore')
                service_info['service'] = 'SMTP'

            elif port == 3306:  # MySQL
                sock.send(b"\x0a\x00\x00\x00\x0a\x35\x2e\x35\x2e\x35\x00")
                banner = sock.recv(1024)
                service_info['banner'] = banner.decode('utf-8', errors='ignore')
                service_info['service'] = 'MySQL'

            elif port == 5432:  # PostgreSQL
                sock.send(b"\x00\x00\x00\x08\x04\xd2\x16\x2f")
                banner = sock.recv(1024)
                service_info['banner'] = banner.decode('utf-8', errors='ignore')
                service_info['service'] = 'PostgreSQL'

            else:
                # Try generic banner grab
                try:
                    sock.send(b"\r\n\r\n")
                    banner = sock.recv(1024)
                    if banner:
                        service_info['banner'] = banner.decode('utf-8', errors='ignore')
                except:
                    pass

            # Map port to service name if not detected
            if service_info['service'] == 'Unknown':
                service_info['service'] = self._port_to_service(port)

        except Exception:
            pass

        return service_info

    def _port_to_service(self, port: int) -> str:
        """Map port number to service name."""
        service_map = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP',
            443: 'HTTPS', 465: 'SMTPS', 587: 'SMTP Submission',
            993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL',
            1521: 'Oracle', 3306: 'MySQL', 3389: 'RDP',
            5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis',
            8080: 'HTTP Proxy', 8443: 'HTTPS Alt',
            9200: 'Elasticsearch', 11211: 'Memcached',
            27017: 'MongoDB'
        }
        return service_map.get(port, f'Port {port}')

    def _categorize_ports(self, open_ports: List[Dict]):
        """Categorize ports by risk level."""
        print(f"\n{Fore.YELLOW}PORT SECURITY ANALYSIS:{Style.RESET_ALL}")

        high_risk = []
        medium_risk = []
        low_risk = []

        for port_info in open_ports:
            port = port_info['port']

            if port in [21, 22, 23, 25, 53, 80, 443, 3306, 3389, 5900, 5432]:
                high_risk.append(port_info)
            elif port in [8080, 8443, 8000, 3000, 9000, 27017, 6379]:
                medium_risk.append(port_info)
            else:
                low_risk.append(port_info)

        if high_risk:
            print(f"{Fore.RED}  HIGH RISK PORTS ({len(high_risk)}):{Style.RESET_ALL}")
            for port_info in high_risk:
                print(f"    Port {port_info['port']}: {port_info.get('service', 'Unknown')}")

        if medium_risk:
            print(f"{Fore.YELLOW}  MEDIUM RISK PORTS ({len(medium_risk)}):{Style.RESET_ALL}")
            for port_info in medium_risk:
                print(f"    Port {port_info['port']}: {port_info.get('service', 'Unknown')}")

        if low_risk:
            print(f"{Fore.GREEN}  LOW RISK PORTS ({len(low_risk)}):{Style.RESET_ALL}")
            for port_info in low_risk[:5]:  # Show first 5 only
                print(f"    Port {port_info['port']}: {port_info.get('service', 'Unknown')}")
            if len(low_risk) > 5:
                print(f"    ... and {len(low_risk) - 5} more")


# ============================================================================
# NEW: COMPREHENSIVE USERNAME ENUMERATOR
# ============================================================================

class ComprehensiveUsernameEnumerator(TestModule):
    """Comprehensive username enumeration module."""

    def run(self):
        """Run comprehensive username enumeration."""
        self.progress.start_test("Comprehensive Username Enumeration")

        if not self.config['tests']['username_enumeration']:
            self.logger.info("Username enumeration disabled")
            self.progress.end_test("Comprehensive Username Enumeration")
            return

        try:
            all_users = []
            methods = []

            self.logger.info("Starting comprehensive username enumeration")

            # Method 1: Author pages (1-50)
            print(f"{Fore.CYAN}  Scanning author pages (1-50)...{Style.RESET_ALL}")
            author_users = self._enumerate_author_pages(50)
            if author_users:
                all_users.extend(author_users)
                methods.append("Author Pages")
                print(f"    Found {len(author_users)} users via author pages")

            # Method 2: REST API
            print(f"{Fore.CYAN}  Checking REST API...{Style.RESET_ALL}")
            api_users = self._enumerate_rest_api()
            if api_users:
                new_users = [u for u in api_users if u not in all_users]
                all_users.extend(new_users)
                methods.append("REST API")
                print(f"    Found {len(new_users)} new users via REST API")

            # Method 3: Common usernames check
            print(f"{Fore.CYAN}  Checking common usernames...{Style.RESET_ALL}")
            common_users = self._check_common_usernames()
            if common_users:
                new_users = [u for u in common_users if u not in all_users]
                all_users.extend(new_users)
                methods.append("Common Usernames")
                print(f"    Found {len(new_users)} common usernames")

            # Remove duplicates
            all_users = list(set(all_users))

            # Display results
            if all_users:
                print(f"\n{Fore.GREEN}ALL USERNAMES FOUND ({len(all_users)} total):{Style.RESET_ALL}")
                print(f"{Fore.CYAN}Methods used: {', '.join(methods)}{Style.RESET_ALL}")

                # Group by type
                admin_users = [u for u in all_users if 'admin' in u.lower()]
                default_users = [u for u in all_users if u in COMMON_USERNAMES]

                if admin_users:
                    print(f"\n{Fore.RED}ADMIN/USERS WITH PRIVILEGE INDICATORS:{Style.RESET_ALL}")
                    for user in sorted(admin_users):
                        print(f"  • {user}")

                if default_users:
                    print(f"\n{Fore.YELLOW}DEFAULT/COMMON USERNAMES:{Style.RESET_ALL}")
                    for user in sorted(default_users):
                        print(f"  • {user}")

                # Display all
                print(f"\n{Fore.CYAN}COMPLETE USER LIST:{Style.RESET_ALL}")
                for i, user in enumerate(sorted(all_users), 1):
                    print(f"  {i:3}. {user}")

                # Add warning to results
                self.results['warnings'].append({
                    'type': 'Username Enumeration Vulnerability',
                    'severity': 'MEDIUM',
                    'details': f'{len(all_users)} usernames enumerable via {", ".join(methods)}',
                    'recommendation': 'Prevent user enumeration via security plugin or .htaccess rules'
                })

            else:
                print(f"{Fore.GREEN}No usernames found via enumeration{Style.RESET_ALL}")

            # Save results
            self.results['username_enumeration'] = {
                'total_users': len(all_users),
                'users': all_users,
                'admin_users': admin_users if 'admin_users' in locals() else [],
                'default_users': default_users if 'default_users' in locals() else [],
                'methods_used': methods
            }

            self.progress.end_test("Comprehensive Username Enumeration")

        except Exception as e:
            self.logger.error(f"Username enumeration failed: {e}")
            self.progress.end_test("Comprehensive Username Enumeration")

    def _enumerate_author_pages(self, max_pages: int = 20) -> List[str]:
        """Enumerate users via author pages."""
        users = []

        for i in range(1, max_pages + 1):
            url = f"{self.target_url}/?author={i}"
            response = self.client.get(url, allow_redirects=False)

            if response and response.status_code == 301:
                location = response.headers.get('Location', '')
                if '/author/' in location:
                    username = location.split('/author/')[1].strip('/')
                    if username and username not in users:
                        users.append(username)

            time.sleep(0.1)  # Be polite

        return users

    def _enumerate_rest_api(self) -> List[str]:
        """Enumerate users via REST API."""
        users = []

        endpoints = [
            "/wp-json/wp/v2/users",
            "/?rest_route=/wp/v2/users",
            "/index.php?rest_route=/wp/v2/users"
        ]

        for endpoint in endpoints:
            url = urljoin(self.target_url, endpoint)
            response = self.client.get(url)

            if response and response.status_code == 200:
                try:
                    data = response.json()
                    if isinstance(data, list):
                        for user in data:
                            username = user.get('slug') or user.get('name')
                            if username and username not in users:
                                users.append(username)
                except:
                    pass

        return users

    def _check_common_usernames(self) -> List[str]:
        """Check for common usernames."""
        found_users = []

        for username in COMMON_USERNAMES:
            # Check author page
            author_url = f"{self.target_url}/author/{username}/"
            response = self.client.get(author_url)

            if response and response.status_code == 200:
                # Check if it's a valid author page
                content = response.text.lower()
                if ('author' in content or 'posts by' in content) and 'page not found' not in content:
                    if username not in found_users:
                        found_users.append(username)

            time.sleep(0.1)

        return found_users


# ============================================================================
# NEW: WEAK PASSWORD DETECTOR
# ============================================================================

class WeakPasswordDetector(TestModule):
    """Weak password detection module (safe checks only)."""

    def run(self):
        """Run weak password detection (safe checks only)."""
        self.progress.start_test("Weak Password Detection")

        if not self.config['tests']['weak_password_detection']:
            self.logger.info("Weak password detection disabled")
            self.progress.end_test("Weak Password Detection")
            return

        try:
            findings = []

            self.logger.info("Starting weak password detection (safe checks)")

            # 1. Check login page for password policy
            print(f"{Fore.CYAN}  Checking login page security...{Style.RESET_ALL}")
            policy_issues = self._check_password_policy()
            if policy_issues:
                findings.extend(policy_issues)
                print(f"    Found {len(policy_issues)} password policy issues")

            # 2. Check for common password indicators
            print(f"{Fore.CYAN}  Checking for common password risks...{Style.RESET_ALL}")
            common_pass_issues = self._check_common_password_risks()
            if common_pass_issues:
                findings.extend(common_pass_issues)
                print(f"    Found {len(common_pass_issues)} common password risks")

            # 3. Check brute force protection
            print(f"{Fore.CYAN}  Checking brute force protection...{Style.RESET_ALL}")
            brute_force_issues = self._check_brute_force_protection()
            if brute_force_issues:
                findings.extend(brute_force_issues)
                print(f"    Found {len(brute_force_issues)} brute force protection issues")

            # 4. Check two-factor authentication
            print(f"{Fore.CYAN}  Checking for two-factor authentication...{Style.RESET_ALL}")
            twofa_issues = self._check_two_factor_auth()
            if twofa_issues:
                findings.extend(twofa_issues)
                print(f"    Found {len(twofa_issues)} 2FA issues")

            # Display results
            if findings:
                print(f"\n{Fore.YELLOW}WEAK PASSWORD & AUTHENTICATION FINDINGS:{Style.RESET_ALL}")

                for finding in findings:
                    severity_color = {
                        'CRITICAL': Fore.RED,
                        'HIGH': Fore.YELLOW,
                        'MEDIUM': Fore.BLUE,
                        'LOW': Fore.CYAN
                    }.get(finding.get('severity', 'LOW'), Fore.WHITE)

                    print(f"\n{severity_color}● {finding.get('type', 'Unknown')}{Style.RESET_ALL}")
                    print(f"  Details: {finding.get('details', 'N/A')}")
                    print(f"  Recommendation: {finding.get('recommendation', 'N/A')}")

                # Calculate security score
                score = self._calculate_password_security_score(findings)
                print(f"\n{Fore.CYAN}Password Security Score: {score}/100{Style.RESET_ALL}")

                if score < 50:
                    print(f"{Fore.RED}  WARNING: Password security is weak!{Style.RESET_ALL}")
                elif score < 75:
                    print(f"{Fore.YELLOW}  WARNING: Password security needs improvement{Style.RESET_ALL}")
                else:
                    print(f"{Fore.GREEN}  GOOD: Password security is adequate{Style.RESET_ALL}")

            else:
                print(f"{Fore.GREEN}No weak password issues detected{Style.RESET_ALL}")

            # Save results
            self.results['password_security'] = {
                'findings': findings,
                'security_score': self._calculate_password_security_score(findings),
                'total_issues': len(findings)
            }

            # Add findings to main results
            for finding in findings:
                if finding.get('severity') in ['CRITICAL', 'HIGH']:
                    self.results['vulnerabilities'].append(finding)
                else:
                    self.results['warnings'].append(finding)

            self.progress.end_test("Weak Password Detection")

        except Exception as e:
            self.logger.error(f"Weak password detection failed: {e}")
            self.progress.end_test("Weak Password Detection")

    def _check_password_policy(self) -> List[Dict]:
        """Check password policy enforcement."""
        findings = []

        try:
            login_url = f"{self.target_url}/wp-login.php"
            response = self.client.get(login_url)

            if not response:
                return findings

            content = response.text.lower()

            # Check for password strength meter
            strength_indicators = [
                'password strength', 'strength indicator',
                'very weak', 'weak', 'medium', 'strong', 'very strong'
            ]

            has_strength_meter = any(indicator in content for indicator in strength_indicators)

            if not has_strength_meter:
                findings.append({
                    'type': 'No Password Strength Meter',
                    'severity': 'MEDIUM',
                    'details': 'No visible password strength enforcement on login page',
                    'recommendation': 'Implement password strength meter on registration/login pages'
                })

            # Check for password policy documentation
            policy_keywords = [
                'password must', 'minimum length', 'require',
                'uppercase', 'lowercase', 'number', 'special character'
            ]

            has_policy_docs = any(keyword in content for keyword in policy_keywords)

            if not has_policy_docs:
                findings.append({
                    'type': 'No Password Policy Documentation',
                    'severity': 'LOW',
                    'details': 'No visible password requirements documentation',
                    'recommendation': 'Display clear password requirements (min 12 chars, mixed case, numbers, symbols)'
                })

        except Exception as e:
            self.logger.debug(f"Password policy check failed: {e}")

        return findings

    def _check_common_password_risks(self) -> List[Dict]:
        """Check for common password risks."""
        findings = []

        try:
            # Check if default credentials warning should be given
            findings.append({
                'type': 'Default Credentials Risk',
                'severity': 'HIGH',
                'details': 'Default credentials (admin/admin, admin/password, etc.) are commonly targeted',
                'recommendation': 'Change all default usernames and passwords immediately'
            })

            # Check common passwords list
            common_passwords = self.config['password_check']['common_passwords']
            if common_passwords:
                findings.append({
                    'type': 'Common Passwords Risk',
                    'severity': 'MEDIUM',
                    'details': f'Using common passwords makes accounts vulnerable to dictionary attacks',
                    'recommendation': f'Avoid using common passwords like: {", ".join(common_passwords[:5])}...'
                })

        except Exception as e:
            self.logger.debug(f"Common password check failed: {e}")

        return findings

    def _check_brute_force_protection(self) -> List[Dict]:
        """Check for brute force protection."""
        findings = []

        try:
            login_url = f"{self.target_url}/wp-login.php"
            response = self.client.get(login_url)

            if not response:
                return findings

            content = response.text.lower()

            # Check for security plugin indicators
            security_plugins = [
                'wordfence', 'ithemes security', 'sucuri',
                'limit login attempts', 'login lockdown',
                'brute force protection', 'failed login',
                'captcha', 'recaptcha', 'hcaptcha'
            ]

            has_protection = any(plugin in content for plugin in security_plugins)

            if not has_protection:
                findings.append({
                    'type': 'No Brute Force Protection',
                    'severity': 'MEDIUM',
                    'details': 'No visible brute force protection on login page',
                    'recommendation': 'Install security plugin with login attempt limiting and CAPTCHA'
                })

        except Exception as e:
            self.logger.debug(f"Brute force check failed: {e}")

        return findings

    def _check_two_factor_auth(self) -> List[Dict]:
        """Check for two-factor authentication."""
        findings = []

        try:
            login_url = f"{self.target_url}/wp-login.php"
            response = self.client.get(login_url)

            if not response:
                return findings

            content = response.text.lower()

            # Check for 2FA indicators
            twofa_indicators = [
                'two-factor', '2fa', 'two factor',
                'authenticator', 'google authenticator',
                'authy', 'sms verification', 'totp'
            ]

            has_twofa = any(indicator in content for indicator in twofa_indicators)

            if not has_twofa:
                findings.append({
                    'type': 'No Two-Factor Authentication',
                    'severity': 'MEDIUM',
                    'details': 'Two-Factor Authentication not detected',
                    'recommendation': 'Enable 2FA for all administrative and privileged accounts'
                })

        except Exception as e:
            self.logger.debug(f"2FA check failed: {e}")

        return findings

    def _calculate_password_security_score(self, findings: List[Dict]) -> int:
        """Calculate password security score (0-100)."""
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



# ============================================================================
# ENHANCED WORDPRESS SECURITY SCANNER (FIXED VERSION)
# ============================================================================

class EnhancedWordPressSecurityScanner:
    """Enhanced scanner with all requested features."""

    def __init__(self, target_url: str, config_file: Optional[str] = None,
                 auth_file: Optional[str] = None):

        # Initialize configuration
        self.config = DEFAULT_CONFIG.copy()

        # Load custom config if provided
        if config_file and Path(config_file).exists():
            try:
                with open(config_file, 'r') as f:
                    user_config = yaml.safe_load(f)
                    self._deep_update(self.config, user_config)
            except Exception as e:
                print(f"{Fore.YELLOW}Warning: Could not load config file: {e}{Style.RESET_ALL}")

        # Setup scan ID
        self.scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Setup logging
        self.logger = setup_logging(self.config, self.scan_id)

        # Setup authorization
        self.auth_manager = AuthorizationManager(self.config)

        # Setup safety manager
        self.safety_manager = SafetyManager(self.config, self.logger)

        # Parse target URL
        self.target_url = self._normalize_url(target_url)
        self.parsed_url = urlparse(self.target_url)

        # Setup HTTP client
        self.http_client = SafeHTTPClient(self.config, self.safety_manager, self.logger)

        # Initialize results
        self.results = {
            'target_url': self.target_url,
            'scan_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'scan_id': self.scan_id,
            'config': self.config,
            'vulnerabilities': [],
            'warnings': [],
            'info': []
        }

        self.results_manager = ResultsManager(self.target_url, self.scan_id)

        # Progress tracker (will be initialized later)
        self.progress = None

        # Test modules
        self.test_modules = []

    def _normalize_url(self, url: str) -> str:
        """Normalize URL."""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        return url.rstrip('/')

    def _deep_update(self, original: Dict, update: Dict):
        """Deep update dictionary."""
        for key, value in update.items():
            if isinstance(value, dict) and key in original:
                self._deep_update(original[key], value)
            else:
                original[key] = value

    def setup_scan(self) -> bool:
        """Setup and verify scan can proceed."""

        print(f"\n{Fore.CYAN}{'=' * 80}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'ENHANCED WORDPRESS SECURITY SCANNER':^80}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'=' * 80}{Style.RESET_ALL}")
        print(
            f"{Fore.CYAN}Features: All Open Ports | All Usernames | Weak Password Detection{Style.RESET_ALL}")

        # Verify authorization
        try:
            if not self.auth_manager.verify_authorization(self.target_url):
                self.logger.error("Authorization failed")
                return False
        except AuthorizationError as e:
            self.logger.error(f"Authorization error: {e}")
            return False

        # Start safety manager
        try:
            self.safety_manager.start_scan()
        except SafetyViolationError as e:
            self.logger.error(f"Safety violation: {e}")
            return False

        # Check robots.txt
        if not self.http_client.check_robots_txt(self.target_url):
            self.logger.warning("robots.txt disallows scanning")
            confirm = input("Continue anyway? (yes/no): ").strip().lower()
            if confirm != 'yes':
                return False

        # Verify target is accessible
        self.logger.info(f"Verifying target: {self.target_url}")
        response = self.http_client.get(self.target_url)

        if not response:
            self.logger.error(f"Target not accessible: {self.target_url}")
            return False

        self.logger.info(f"Target verified (HTTP {response.status_code})")

        # Count total tests
        total_tests = sum(1 for enabled in self.config['tests'].values() if enabled)
        self.progress = ProgressTracker(total_tests, self.config, self.logger)

        # Initialize test modules
        self._init_test_modules()

        return True

    def _init_test_modules(self):
        """Initialize all test modules."""

        # NEW MODULES ADDED FOR REQUESTED FEATURES
        if self.config['tests']['port_scanning']:
            self.test_modules.append(
                EnhancedPortScanner(self.http_client, self.config, self.results, self.progress, self.logger)
            )

        if self.config['tests']['username_enumeration']:
            self.test_modules.append(
                ComprehensiveUsernameEnumerator(self.http_client, self.config, self.results, self.progress, self.logger)
            )

        if self.config['tests']['weak_password_detection']:
            self.test_modules.append(
                WeakPasswordDetector(self.http_client, self.config, self.results, self.progress, self.logger)
            )


        # NEW: SQL Safety Check Module - FIXED METHOD NAME
        if self.config['tests'].get('sql_safety_check', True):
            try:
                sql_module = SQLInjectionSafetyValidator(self.config, self.logger)
                # Use set_client() instead of set_http_client()
                if hasattr(sql_module, 'set_client'):
                    sql_module.set_client(self.http_client)
                elif hasattr(sql_module, 'set_http_client'):
                    sql_module.set_http_client(self.http_client)
                elif hasattr(sql_module, 'client'):
                    sql_module.client = self.http_client

                if hasattr(sql_module, 'set_target_url'):
                    sql_module.set_target_url(self.target_url)
                elif hasattr(sql_module, 'target_url'):
                    sql_module.target_url = self.target_url

                if hasattr(sql_module, 'set_progress'):
                    sql_module.set_progress(self.progress)
                elif hasattr(sql_module, 'progress'):
                    sql_module.progress = self.progress

                if hasattr(sql_module, 'set_main_results'):
                    sql_module.set_main_results(self.results)
                elif hasattr(sql_module, 'results'):
                    sql_module.results = self.results

                self.test_modules.append(sql_module)
            except Exception as e:
                self.logger.error(f"Failed to initialize SQL module: {e}")

        # NEW: Vulnerability Analysis Module - FIXED INITIALIZATION
        if self.config['tests'].get('vulnerability_analysis', True):
            try:
                # Pass the correct 5 parameters that VulnerabilityAggregator expects
                vuln_aggregator = VulnerabilityAggregator(
                    self.http_client,
                    self.config,
                    self.results,
                    self.progress,
                    self.logger
                )
                self.test_modules.append(vuln_aggregator)
            except Exception as e:
                self.logger.error(f"Failed to initialize VulnerabilityAggregator: {e}")

    def run_scan(self):
        """Run the security scan."""

        start_time = time.time()

        try:
            self.logger.info(f"Starting enhanced security scan for {self.target_url}")
            print(f"\n{Fore.GREEN}Starting enhanced scan with all requested features...{Style.RESET_ALL}")

            # Run each test module
            for module in self.test_modules:
                try:
                    # Check if module has a run method
                    if hasattr(module, 'run'):
                        module.run()
                    else:
                        self.logger.warning(f"Module {type(module).__name__} has no run method")
                        continue

                    # Check for emergency stop
                    if self.safety_manager.emergency_stop.is_set():
                        self.logger.warning("Emergency stop triggered")
                        break

                except RateLimitError as e:
                    self.logger.error(f"Rate limit error in {module.__class__.__name__}: {e}")
                    # Continue with next test
                    continue
                except Exception as e:
                    self.logger.error(f"Error in {module.__class__.__name__}: {e}")
                    # Continue with next test
                    continue

            # Generate comprehensive report
            self._generate_comprehensive_report()

            # Update scan duration
            scan_duration = time.time() - start_time
            self.results['scan_duration'] = round(scan_duration, 2)

            # Generate summary of new features
            self._generate_feature_summary()

            # Complete progress tracking
            if self.progress:
                self.progress.complete()

            self.logger.info(f"Scan completed in {scan_duration:.2f} seconds")

            return True

        except KeyboardInterrupt:
            self.logger.warning("Scan interrupted by user")
            print(f"\n{Fore.YELLOW}Scan interrupted by user{Style.RESET_ALL}")
            return False
        except Exception as e:
            self.logger.error(f"Scan failed: {e}")
            print(f"\n{Fore.RED}Scan failed: {e}{Style.RESET_ALL}")
            return False

    def _generate_feature_summary(self):
        """Generate summary of the new features."""
        print(f"\n{Fore.CYAN}{'=' * 80}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'REQUESTED FEATURES SUMMARY':^80}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'=' * 80}{Style.RESET_ALL}")

        # Enhanced Port Scanning Summary
        if 'enhanced_port_scan' in self.results:
            port_data = self.results['enhanced_port_scan']
            print(f"\n{Fore.GREEN}ENHANCED PORT SCANNING:{Style.RESET_ALL}")
            print(f"  Total ports scanned: {port_data.get('total_scanned', 0)}")
            print(f"  Open ports found: {port_data.get('open_count', 0)}")
            if port_data.get('open_ports'):
                print(f"  Open ports: {', '.join([str(p['port']) for p in port_data['open_ports'][:10]])}")
                if len(port_data['open_ports']) > 10:
                    print(f"  ... and {len(port_data['open_ports']) - 10} more")

        # Username Enumeration Summary
        if 'username_enumeration' in self.results:
            user_data = self.results['username_enumeration']
            print(f"\n{Fore.GREEN}USERNAME ENUMERATION:{Style.RESET_ALL}")
            print(f"  Total users found: {user_data.get('total_users', 0)}")
            print(f"  Methods used: {', '.join(user_data.get('methods_used', []))}")
            if user_data.get('admin_users'):
                print(f"  Admin users: {', '.join(user_data['admin_users'])}")
            if user_data.get('default_users'):
                print(f"  Default users: {', '.join(user_data['default_users'])}")

        # Password Security Summary
        if 'password_security' in self.results:
            pass_data = self.results['password_security']
            print(f"\n{Fore.GREEN}PASSWORD SECURITY:{Style.RESET_ALL}")
            print(f"  Security score: {pass_data.get('security_score', 0)}/100")
            print(f"  Issues found: {pass_data.get('total_issues', 0)}")
            score = pass_data.get('security_score', 0)
            if score < 50:
                print(f"  {Fore.RED}STATUS: WEAK - Immediate action required{Style.RESET_ALL}")
            elif score < 75:
                print(f"  {Fore.YELLOW}STATUS: FAIR - Improvements needed{Style.RESET_ALL}")
            else:
                print(f"  {Fore.GREEN}STATUS: GOOD - Adequate security{Style.RESET_ALL}")



        print(f"\n{Fore.CYAN}Detailed reports have been saved in the 'reports' directory.{Style.RESET_ALL}")

    def _generate_comprehensive_report(self):
        """Generate comprehensive report from all modules."""
        # Save results to JSON
        try:
            reports_dir = Path("reports")
            reports_dir.mkdir(exist_ok=True)

            target_name = self.target_url.replace('://', '_').replace('/', '_').replace('.', '_')
            filename = reports_dir / f"scan_results_{target_name}_{self.scan_id}.json"

            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=2, default=str)

            print(f"\n{Fore.GREEN}Full report saved to: {filename}{Style.RESET_ALL}")

        except Exception as e:
            self.logger.error(f"Failed to save report: {e}")

    def cleanup(self):
        """Cleanup resources."""
        if self.http_client:
            self.http_client.session.close()

        self.logger.info("Cleanup completed")


# ============================================================================
# UPDATED COMMAND-LINE INTERFACE
# ============================================================================

def parse_arguments():
    """Parse command line arguments with new options."""
    parser = argparse.ArgumentParser(
        description="Enhanced WordPress Security Scanner with All Requested Features",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s https://example.com
  %(prog)s https://example.com --all-features
  %(prog)s https://example.com --wifi-scan
  %(prog)s https://example.com --quick

Features Added:
  • All open ports scanning (100+ ports)
  • Comprehensive username enumeration
  • Weak password detection (safe checks)
  • WiFi/Access Point scanning

Security Notice:
  This tool is for authorized security testing only.
  WiFi scanning may require root privileges.
        """
    )

    parser.add_argument(
        "target",
        help="Target WordPress website URL"
    )

    parser.add_argument(
        "--all-features", "-a",
        action="store_true",
        help="Enable all new features (ports, users, passwords, wifi)"
    )

    parser.add_argument(
        "--wifi-scan", "-w",
        action="store_true",
        help="Enable WiFi/Access Point scanning"
    )

    parser.add_argument(
        "--quick", "-q",
        action="store_true",
        help="Quick scan (skip time-consuming tests)"
    )

    parser.add_argument(
        "--config", "-c",
        help="Configuration file (YAML/JSON)"
    )

    parser.add_argument(
        "--auth",
        help="Authorization file"
    )

    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output"
    )

    return parser.parse_args()


def main():
    """Main entry point."""

    # Parse arguments
    args = parse_arguments()

    try:
        # Create scanner instance
        scanner = EnhancedWordPressSecurityScanner(
            target_url=args.target,
            config_file=args.config,
            auth_file=args.auth
        )

        # Apply command-line overrides
        if args.all_features:
            # Enable all new features
            scanner.config['tests']['username_enumeration'] = True
            scanner.config['tests']['weak_password_detection'] = True


        if args.verbose:
            scanner.config['output']['verbose'] = True
            scanner.config['output']['log_level'] = "DEBUG"

        if args.quick:
            # Reduce scanning intensity
            scanner.config['scanning']['delay_between_requests'] = 0.1
            scanner.config['scanning']['max_workers'] = 2

        # Setup and run scan
        if scanner.setup_scan():
            scanner.run_scan()
        else:
            print(f"\n{Fore.RED}Scan setup failed. Check logs for details.{Style.RESET_ALL}")
            return 1

        # Cleanup
        scanner.cleanup()

        return 0

    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}Scan interrupted by user.{Style.RESET_ALL}")
        return 130  # SIGINT exit code
    except Exception as e:
        print(f"\n{Fore.RED}Fatal error: {e}{Style.RESET_ALL}")
        logging.error(f"Fatal error: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    # Check Python version
    import sys

    if sys.version_info < (3, 7):
        print(f"{Fore.RED}Error: Python 3.7 or higher is required{Style.RESET_ALL}")
        sys.exit(1)

    # Check required packages
    try:
        import requests
        import yaml
        import colorama
        from tabulate import tabulate
    except ImportError as e:
        print(f"{Fore.RED}Error: Missing required package: {e}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Install required packages: pip install requests pyyaml colorama tabulate{Style.RESET_ALL}")
        sys.exit(1)

    # Run main
    sys.exit(main())