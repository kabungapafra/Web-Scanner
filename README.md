# Comprehensive Web Security Scanner

A professional-grade security scanning suite that combines multiple specialized modules to perform deep security assessments of web applications, APIs, and WordPress installations. This tool integrates OSINT reconnaissance, vulnerability detection, API security testing, threat intelligence, and advanced exploitation capabilities.

## 🚀 Features

### Core Scanning Modules

- **🔍 OSINT Scanner**: Subdomain enumeration, email harvesting, technology stack detection, and passive reconnaissance
- **🛡️ WordPress Security Scanner**: 
  - Core/plugin/theme vulnerability detection
  - User enumeration and weak password testing
  - Configuration security analysis
  - Honeypot and social engineering detection
- **🔐 Comprehensive Vulnerability Scanner**: 
  - SQL Injection (SQLi) detection
  - Cross-Site Scripting (XSS) testing
  - Path Traversal vulnerabilities
  - Security header analysis
  - SSL/TLS configuration testing
  - Port scanning (100+ common ports)
- **🌐 API Security Scanner**: 
  - REST/GraphQL endpoint discovery
  - JWT token analysis
  - IDOR (Insecure Direct Object Reference) testing
  - API authentication bypass detection
  - Rate limiting and input validation checks

### Advanced Capabilities

- **🎯 Metasploit Integration**: Automated exploit matching and vulnerability verification
- **🔬 Threat Intelligence**: Real-time threat data correlation and risk scoring
- **📊 Detailed Remediation Guidance**: Step-by-step security improvement recommendations
- **📝 Comprehensive Reporting**: JSON-formatted results with console output capture

## 📋 Prerequisites

- **Python**: 3.8 or higher
- **Operating System**: Linux, macOS, or Windows (WSL recommended)
- **Network**: Internet connection for OSINT and threat intelligence features
- **Optional**: Metasploit Framework (for exploit integration features)

## 🔧 Installation

### 1. Clone the Repository
```bash
git clone <repository-url>
cd "Web Scanner"
```

### 2. Create Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configuration (Optional)
Edit `config/config.yaml` to customize scanner behavior:
- Enable/disable specific modules
- Configure API keys for threat intelligence
- Set scanning intensity and timeouts
- Customize reporting options

## 🎯 Usage

### Basic Scan
Run a complete security assessment with all features enabled:

```bash
./venv/bin/python3 unified_scanner.py https://example.com --all-features
```

### Command-Line Options

```bash
unified_scanner.py <target_url> [options]

Positional Arguments:
  target_url              Target URL to scan (e.g., https://example.com)

Optional Arguments:
  --all-features, -a      Enable all scanner features (recommended)
  --output FILE           Specify custom output file path
                         Default: unified_scan_results_YYYYMMDD_HHMMSS.json
```

### Scan Execution Flow

The unified scanner executes in the following order:

1. **[1/4] OSINT Scanner**: Gathers intelligence on subdomains, emails, and technology stack
2. **[2/4] WordPress Scanner**: Analyzes WordPress-specific vulnerabilities and configurations
3. **[3/4] Comprehensive Scanner**: Tests for common web vulnerabilities (SQLi, XSS, etc.)
4. **[4/4] API Security Scanner**: Evaluates API endpoints and authentication mechanisms

### Output

- **Console**: Real-time progress updates and findings displayed in terminal
- **JSON Report**: Detailed results saved to timestamped file (e.g., `unified_scan_results_20251220_132405.json`)
- **Remediation Section**: Prioritized security recommendations with step-by-step fixes

## 📁 Project Structure

```
Web Scanner/
├── unified_scanner.py          # Main entry point
├── requirements.txt            # Python dependencies
├── config/
│   └── config.yaml            # Scanner configuration
├── modules/
│   ├── osint.py               # OSINT reconnaissance
│   ├── wordpress_scanner.py   # WordPress security testing
│   ├── comprehensive_scanner.py # Vulnerability scanning
│   ├── api_security.py        # API security assessment
│   ├── metasploit.py          # Metasploit integration
│   ├── threat_intel.py        # Threat intelligence
│   └── sql_safety_module.py   # SQL injection detection
├── core/                      # Core utilities and helpers
├── reports/                   # Generated scan reports
└── scanner_logs/              # Execution logs
```

## 🔍 Example Scan Output

```bash
--- Starting Unified Scan for https://example.com ---

[1/4] Running OSINT Scanner...
✓ Found 5 subdomains
✓ Discovered 3 email addresses
✓ Technology stack: WordPress 6.4, PHP 8.1, Nginx

[2/4] Running Enhanced WordPress Security Scanner...
⚠ Found 2 outdated plugins
⚠ Username enumeration possible
✓ SSL/TLS properly configured

[3/4] Running Comprehensive Security Scanner...
⚠ Potential XSS vulnerability detected
✓ No SQL injection vulnerabilities found
⚠ Missing security headers: X-Frame-Options, CSP

[4/4] Running API Security Scanner...
✓ Found 8 API endpoints
⚠ JWT signature not verified
⚠ Rate limiting not implemented

================================================================================
                      REMEDIATION & IMPROVEMENTS
================================================================================
[HIGH] XSS Vulnerability
   Detailed Remediation Plan:
     1. Implement Context-Aware Output Encoding for all user-supplied data
     2. Deploy a Content Security Policy (CSP)
     3. Use modern frameworks that handle escaping by default
     ...

--- Unified Scan Finished ---
Unified scan results saved to: unified_scan_results_20251220_132405.json
```

## 🛠️ Troubleshooting

### Common Issues

**Issue**: `ModuleNotFoundError: No module named 'requests'`
- **Solution**: Ensure virtual environment is activated and dependencies are installed:
  ```bash
  source venv/bin/activate
  pip install -r requirements.txt
  ```

**Issue**: `Connection timeout` errors
- **Solution**: Check network connectivity and firewall settings. Some targets may block automated scanners.

**Issue**: Metasploit integration fails
- **Solution**: Ensure Metasploit Framework is installed and `msfrpcd` is running. This feature is optional.

**Issue**: `Permission denied` when running scanner
- **Solution**: Make the script executable:
  ```bash
  chmod +x unified_scanner.py
  ```

### Getting Help

If you encounter issues:
1. Check the `scanner_logs/` directory for detailed error logs
2. Review the `config/config.yaml` file for misconfigurations
3. Ensure all dependencies are up to date: `pip install --upgrade -r requirements.txt`

## ⚖️ Legal Disclaimer

> [!CAUTION]
> **AUTHORIZED TESTING ONLY**
> 
> This tool is designed for **security professionals, penetration testers, and authorized security assessments only**.
> 
> - ✅ **DO**: Use on systems you own or have explicit written permission to test
> - ✅ **DO**: Obtain proper authorization before scanning any target
> - ✅ **DO**: Comply with all applicable laws and regulations
> - ❌ **DON'T**: Use for unauthorized access or malicious purposes
> - ❌ **DON'T**: Scan systems without explicit permission
> 
> **Unauthorized access to computer systems is illegal.** The developers assume no liability for misuse of this tool.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please ensure:
- Code follows existing style conventions
- New features include appropriate documentation
- Security modules are thoroughly tested
- All changes respect ethical hacking principles

## 📚 Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [WordPress Security Best Practices](https://wordpress.org/support/article/hardening-wordpress/)
- [API Security Best Practices](https://owasp.org/www-project-api-security/)

---

**Version**: 2.0  
**Last Updated**: December 2025
