#!/usr/bin/env python3
"""
Unified Security Scanner
Combines the Comprehensive Security Scanner and the WordPress Security Scanner
to provide a single, consolidated report.
"""

import argparse
import json
import sys
from datetime import datetime
from io import StringIO
import os
import time
import yaml
import logging

class StreamToCallback:
    """
    Redirects writes to a callback function while optionally maintaining
    the original stream (like stdout).
    """
    def __init__(self, callback, original_stream=None):
        self.callback = callback
        self.original_stream = original_stream

    def write(self, buf):
        if self.original_stream:
            self.original_stream.write(buf)
        if buf.strip():  # Only callback for non-empty content to avoid noise
            self.callback(buf)

    def flush(self):
        if self.original_stream:
            self.original_stream.flush()


# Add the current directory to sys.path to ensure modules can be imported
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from modules.wordpress_scanner import EnhancedWordPressSecurityScanner
    from modules.comprehensive_scanner import ComprehensiveSecurityScanner
    from modules.api_security import APISecurityScanner
    from modules.osint import OSINTScanner
    # Detailed remediations are now in a separate file or kept here?
    # For now, we keep the DETAILED_REMEDIATIONS in unified_scanner.py or move them?
    # The user didn't ask to move them, but it would be cleaner.
    # I'll keep them here for now to minimize changes, or move them to core/remediation.py
except ImportError as e:



    sys.exit(1)


# ============================================================================
# DETAILED REMEDIATION KNOWLEDGE BASE
# ============================================================================

DETAILED_REMEDIATIONS = {
    'SQL Injection': [
        "Use Prepared Statements (Parameterized Queries) for all database access.",
        "Implement strict Input Validation (allow-listing) for all user inputs.",
        "Use an ORM (Object-Relational Mapping) framework that handles escaping automatically.",
        "Apply the Principle of Least Privilege to database accounts.",
        "Deploy a Web Application Firewall (WAF) to block malicious SQL patterns."
    ],
    'XSS': [
        "Implement Context-Aware Output Encoding for all user-supplied data.",
        "Deploy a Content Security Policy (CSP) to restrict script execution sources.",
        "Use modern frameworks (React, Vue, Angular) that handle escaping by default.",
        "Sanitize HTML input using a trusted library (e.g., DOMPurify) if rich text is required.",
        "Set the 'HttpOnly' flag on session cookies to prevent theft via XSS."
    ],
    'Weak Password': [
        "Enforce a strong password policy (min 12 chars, mixed case, numbers, symbols).",
        "Implement Multi-Factor Authentication (MFA/2FA) for all accounts.",
        "Check passwords against a database of breached credentials (e.g., Have I Been Pwned).",
        "Implement rate limiting and account lockout policies to prevent brute force.",
        "Educate users about the risks of password reuse."
    ],
    'Default Credentials': [
        "Immediately change the password for the identified default account.",
        "If the account is not needed, disable or delete it entirely.",
        "Review all other systems/services for similar default credentials.",
        "Ensure the new password follows the organization's strong password policy."
    ],
    'Open Port': [
        "Verify if this service is required for business operations.",
        "If not required, stop the service and disable it from starting on boot.",
        "If required, restrict access using a firewall (allow only necessary IPs).",
        "Ensure the service is patched and running the latest secure version.",
        "Consider moving the service to a non-standard port (security through obscurity, but helps reduce noise)."
    ],
    'Username Enumeration': [
        "Disable the REST API user endpoints (/wp-json/wp/v2/users) if not needed.",
        "Use a security plugin to block author archive scans (/?author=N).",
        "Implement a Web Application Firewall (WAF) to block enumeration attempts.",
        "Ensure generic error messages are used for login failures (don't reveal if username exists)."
    ],
    'SSL/TLS': [
        "Obtain and install a valid SSL/TLS certificate from a trusted CA (e.g., Let's Encrypt).",
        "Configure the web server to enforce HTTPS (redirect HTTP to HTTPS).",
        "Disable support for old protocols (SSLv3, TLS 1.0, TLS 1.1).",
        "Configure strong cipher suites and disable weak ones (e.g., RC4, NULL).",
        "Implement HSTS (HTTP Strict Transport Security) headers."
    ],
    'Honeypot': [
        "Review the identified endpoint; if it's a legitimate security tool, ensure it's properly configured.",
        "If it's a malicious trap left by an attacker, isolate the system and perform forensic analysis.",
        "Ensure honeypots do not expose real system vulnerabilities or data."
    ],
    'Social Engineering': [
        "Review the content for manipulative language (urgency, fear, authority).",
        "Implement security awareness training for users/employees.",
        "Ensure all official communications follow a standard, verifiable format.",
        "Remove any fake login forms or deceptive UI elements."
    ]
}


def print_remediation_section(all_results):
    """
    Extracts and prints detailed remediation suggestions from all scan results.
    """
    print(f"\n\033[36m{'=' * 80}\033[0m")
    print(f"\033[36m{' ' * 22}REMEDIATION & IMPROVEMENTS{' ' * 22}\033[0m")
    print(f"\033[36m{'=' * 80}\033[0m")

    recommendations = []

    # Helper to add recommendation
    def add_rec(finding, source):
        if isinstance(finding, dict):
            # Determine the type for detailed remediation lookup
            finding_type = finding.get('type', '')
            details = finding.get('description') or finding.get('details') or finding_type
            
            # Find matching detailed remediation
            detailed_steps = []
            for key, steps in DETAILED_REMEDIATIONS.items():
                if key.lower() in finding_type.lower() or key.lower() in details.lower():
                    detailed_steps = steps
                    break
            
            # Fallback to the generic recommendation if no detailed steps found
            rec_text = finding.get('recommendation', 'Review and secure this configuration.')
            
            severity = finding.get('severity', 'LOW')
            
            # Create a unique key to avoid duplicates
            unique_key = f"{finding_type}:{details}"
            
            if not any(r['key'] == unique_key for r in recommendations):
                recommendations.append({
                    'key': unique_key,
                    'type': finding_type,
                    'details': details,
                    'severity': severity,
                    'source': source,
                    'generic_rec': rec_text,
                    'detailed_steps': detailed_steps
                })

    # 1. Extract from WordPress Scanner
    wp_results = all_results.get('wordpress_scan')
    if wp_results and isinstance(wp_results, dict):
        # Vulnerabilities
        for v in wp_results.get('vulnerabilities', []):
            add_rec(v, 'WordPress Scanner')
        # Warnings
        for w in wp_results.get('warnings', []):
            add_rec(w, 'WordPress Scanner')
        # Password Security
        pwd_sec = wp_results.get('password_security', {})
        if pwd_sec:
            for f in pwd_sec.get('findings', []):
                add_rec(f, 'Password Security')

    # 2. Extract from Comprehensive Scanner
    comp_results = all_results.get('comprehensive_scan')
    if comp_results and isinstance(comp_results, dict):
        # Iterate over all list fields as they might contain findings
        for key, value in comp_results.items():
            if isinstance(value, list):
                for item in value:
                    add_rec(item, 'Comprehensive Scanner')

    # Sort by severity (Critical/High first)
    severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
    recommendations.sort(key=lambda x: severity_order.get(x['severity'], 5))

    if not recommendations:
        print("\n\033[32mNo specific remediation steps required. Great job!\033[0m")
        return

    print("\nBased on the scan results, here are the detailed actions to secure your website:\n")

    for i, rec in enumerate(recommendations, 1):
        severity = rec['severity']
        color = "\033[37m" # White
        if severity == 'CRITICAL': color = "\033[31m" # Red
        elif severity == 'HIGH': color = "\033[33m" # Yellow
        elif severity == 'MEDIUM': color = "\033[34m" # Blue
        elif severity == 'LOW': color = "\033[36m" # Cyan

        print(f"{color}[{severity}] {rec['type']}\033[0m")
        print(f"   Details: {rec['details']}")
        
        if rec['detailed_steps']:
            print(f"   \033[1mDetailed Remediation Plan:\033[0m")
            for step_idx, step in enumerate(rec['detailed_steps'], 1):
                print(f"     {step_idx}. {step}")
        else:
            print(f"   \u2192 \033[1mRecommendation:\033[0m {rec['generic_rec']}")
        
        print("")

    print(f"\033[36m{'=' * 80}\033[0m\n")


def run_unified_scan(target_url: str, output_file: str, all_features: bool = False, progress_callback=None):
    """
    Runs both scanners and combines their results into a single JSON file.
    The console output of each scanner is captured and included in the final report.
    
    Args:
        target_url: The URL to scan.
        output_file: Path to save the JSON results.
        all_features: Enable all scanner features.
        progress_callback: Optional function to receive real-time output (str).
    """
    print(f"--- Starting Unified Scan for {target_url} ---")
    if progress_callback:
        progress_callback(f"--- Starting Unified Scan for {target_url} ---")

    all_results = {
        'unified_scan_metadata': {
            'target_url': target_url,
            'scan_timestamp': datetime.now().isoformat(),
        },
        'comprehensive_scan': None,
        'wordpress_scan': None,
        'api_security_scan': None,
        'osint_scan': None
    }

    # Load Configuration
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config', 'config.yaml')
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
    except Exception as e:
        print(f"Warning: Could not load config.yaml: {e}. Using defaults.")
        config = {
            'modules': {
                'api_security': {'enabled': True},
                'osint': {'enabled': True}
            }
        }

    # Force enable modules if all_features is True
    if all_features:
        if 'modules' not in config: config['modules'] = {}
        if 'api_security' not in config['modules']: config['modules']['api_security'] = {}
        if 'osint' not in config['modules']: config['modules']['osint'] = {}
        
        config['modules']['api_security']['enabled'] = True
        config['modules']['osint']['enabled'] = True

    # Setup Logger (Basic)
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger("unified_scanner")

    # Redirect stdout to capture the output of the scanners
    original_stdout = sys.stdout
    
    # --- [1/4] Run OSINT Scanner ---
    print("\n[1/4] Running OSINT Scanner...")
    if progress_callback:
        progress_callback("\n[1/4] Running OSINT Scanner...")
        
    captured_osint_output = StringIO()
    if progress_callback:
        sys.stdout = StreamToCallback(progress_callback, captured_osint_output)
    else:
        sys.stdout = captured_osint_output
        
    try:
        osint_scanner = OSINTScanner(config, logger)
        osint_results = osint_scanner.run_scan(target_url) # OSINT usually takes domain, but let's pass URL, module handles it?
        # Check osint.py: run_scan(target_domain)
        # We need to extract domain from URL
        from urllib.parse import urlparse
        domain = urlparse(target_url).netloc
        osint_results = osint_scanner.run_scan(domain)
        
        sys.stdout = original_stdout
        print(captured_osint_output.getvalue())
        print("OSINT Scanner finished.")
        all_results['osint_scan'] = osint_results
        all_results['osint_scan']['console_output'] = captured_osint_output.getvalue()
    except Exception as e:
        sys.stdout = original_stdout
        print(f"Error running OSINT Scanner: {e}")
        all_results['osint_scan'] = {'error': str(e), 'console_output': captured_osint_output.getvalue()}

    # --- [2/4] Run Enhanced WordPress Security Scanner ---
    print("\n[2/4] Running Enhanced WordPress Security Scanner...")
    if progress_callback:
        progress_callback("\n[2/4] Running Enhanced WordPress Security Scanner...")
        
    # Setup output capture
    captured_wp_output = StringIO()
    
    if progress_callback:
        # If we have a callback, we want to stream to it AND capture to StringIO
        # We replace sys.stdout with our custom streamer
        sys.stdout = StreamToCallback(progress_callback, captured_wp_output)
    else:
        # Standard capture
        sys.stdout = captured_wp_output

    try:
        wp_scanner = EnhancedWordPressSecurityScanner(target_url=target_url)
        
        # Disable verbose output and authorization prompts for library use
        wp_scanner.config['safety']['require_authorization'] = False
        wp_scanner.config['output']['verbose'] = False
        wp_scanner.config['output']['progress_bar'] = False
        wp_scanner.config['output']['color_output'] = False
        wp_scanner.config['output']['log_level'] = "ERROR"

        # Apply feature overrides
        if all_features:
            wp_scanner.config['tests']['username_enumeration'] = True
            wp_scanner.config['tests']['weak_password_detection'] = True


        if wp_scanner.setup_scan():
            wp_scanner.run_scan()
            sys.stdout = original_stdout
            print(captured_wp_output.getvalue())
            print("Enhanced WordPress Security Scanner finished.")
            all_results['wordpress_scan'] = wp_scanner.results
        else:
            sys.stdout = original_stdout
            print("Enhanced WordPress Security Scanner setup failed.")
            all_results['wordpress_scan'] = {'error': 'Setup failed.'}
        
        all_results['wordpress_scan']['console_output'] = captured_wp_output.getvalue()

    except Exception as e:
        sys.stdout = original_stdout
        print(f"Error running Enhanced WordPress Security Scanner: {e}")
        all_results['wordpress_scan'] = {'error': str(e), 'console_output': captured_wp_output.getvalue()}
    finally:
        sys.stdout = original_stdout

    # --- [3/4] Run Comprehensive Security Scanner ---
    # --- [3/4] Run Comprehensive Security Scanner ---
    print("\n[3/4] Running Comprehensive Security Scanner...")
    if progress_callback:
        progress_callback("\n[3/4] Running Comprehensive Security Scanner...")

    captured_comp_output = StringIO()
    
    if progress_callback:
        sys.stdout = StreamToCallback(progress_callback, captured_comp_output)
    else:
        sys.stdout = captured_comp_output
    try:
        comp_config = {'verbose': False}
        comp_scanner = ComprehensiveSecurityScanner(target_url, config=comp_config)
        comp_results = comp_scanner.run_comprehensive_scan()
        
        # Restore stdout to print progress
        sys.stdout = original_stdout
        print(captured_comp_output.getvalue())
        print("Comprehensive Security Scanner finished.")
        
        all_results['comprehensive_scan'] = comp_results
        all_results['comprehensive_scan']['console_output'] = captured_comp_output.getvalue()

    except Exception as e:
        sys.stdout = original_stdout
        print(f"Error running Comprehensive Security Scanner: {e}")
        all_results['comprehensive_scan'] = {'error': str(e), 'console_output': captured_comp_output.getvalue()}
    finally:
        sys.stdout = original_stdout

    # --- [4/4] Run API Security Scanner ---
    print("\n[4/4] Running API Security Scanner...")
    if progress_callback:
        progress_callback("\n[4/4] Running API Security Scanner...")
        
    captured_api_output = StringIO()
    if progress_callback:
        sys.stdout = StreamToCallback(progress_callback, captured_api_output)
    else:
        sys.stdout = captured_api_output
        
    try:
        api_scanner = APISecurityScanner(config, logger)
        api_results = api_scanner.run_scan(target_url)
        
        sys.stdout = original_stdout
        print(captured_api_output.getvalue())
        print("API Security Scanner finished.")
        all_results['api_security_scan'] = api_results
        all_results['api_security_scan']['console_output'] = captured_api_output.getvalue()
    except Exception as e:
        sys.stdout = original_stdout
        print(f"Error running API Security Scanner: {e}")
        all_results['api_security_scan'] = {'error': str(e), 'console_output': captured_api_output.getvalue()}

    # --- Save Combined Results ---
    
    # Print Remediation Section
    try:
        print_remediation_section(all_results)
    except Exception as e:
        print(f"Error generating remediation section: {e}")

    # --- [3/3] Run Metasploit Analysis (if enabled) ---
    # This is a placeholder for the integration. 
    # In a real scenario, we would load the config, check if enabled, and run it.
    # For now, we just show it's ready to be integrated.
    
    # Example integration logic (commented out until config loading is fully refactored):
    # try:
    #     from modules.metasploit import MetasploitScanner
    #     # We need to load the full config here, currently unified_scanner doesn't load config.yaml
    #     # It relies on the scanners having their own config.
    #     # We should load config.yaml at the start of main.
    # except ImportError:
    #     pass

    print(f"\n--- Unified Scan Finished ---")
    try:
        with open(output_file, 'w') as f:
            json.dump(all_results, f, indent=2, default=str)
        print(f"Unified scan results saved to: {output_file}")
    except Exception as e:
        print(f"Error saving unified results: {e}")


def main():
    """Main execution function."""
    parser = argparse.ArgumentParser(
        description='Unified Security Scanner',
        epilog="Runs both the Comprehensive and WordPress scanners and combines the results."
    )

    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument(
        '--output',
        default=f"unified_scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
        help='Output file for the combined scan results.'
    )
    
    parser.add_argument(
        '--all-features', '-a',
        action='store_true',
        help='Enable all new features (ports, users, passwords)'
    )

    args = parser.parse_args()

    run_unified_scan(args.url, args.output, args.all_features)


if __name__ == "__main__":
    main()
