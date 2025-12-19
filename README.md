# Professional WordPress Security Scanner

A comprehensive security scanning suite for WordPress websites, combining traditional vulnerability assessment with advanced features like honeypot detection and quantum-resistant security analysis.

## Features

- **Port Scanning**: Enhanced scanning of over 100+ common ports.
- **Vulnerability Assessment**: Checks for XSS, SQL Injection, Path Traversal, and more.
- **WordPress Specifics**: Enumerates users, checks for weak passwords, and detects plugins/themes.
- **Advanced Security**:
    - Honeypot Detection & Social Engineering Analysis
    - Quantum-Resistant Security Assessment
- **Reporting**: Generates detailed JSON reports and console output.

## Installation

1.  **Prerequisites**: Python 3.8 or higher.
2.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

## Usage
 
 ### Unified Scanner (Single Command)
 Runs the complete security suite:
 1. **OSINT Scanner**: Subdomains, emails, tech stack.
 2. **WordPress Scanner**: Core, plugins, themes, users, passwords.
 3. **Comprehensive Scanner**: SQLi, XSS, vulnerabilities.
 4. **API Security Scanner**: Endpoints, JWT, IDOR.
 
 ```bash
 ./venv/bin/python3 unified_scanner.py <target_url> --all-features
 ```
 
 Example:
 ```bash
 ./venv/bin/python3 unified_scanner.py https://example.com --all-features
 ```
 
 ### Output
 Results are displayed in the terminal in real-time and saved to a JSON file (e.g., `unified_scan_results_YYYYMMDD_HHMMSS.json`).
 
 ## Verification
 
 To verify your installation and environment:
 
 ```bash
 ./venv/bin/python3 verify_phase1.py
 ```
 
 ## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer
 
**Authorized Testing Only**: This tool is for educational and security assessment purposes only. Ensure you have explicit authorization before scanning any target.
