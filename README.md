# Vulnerable Python Project

⚠️ **WARNING: This project contains intentional security vulnerabilities!**

This project is designed for educational purposes.
## Project Structure

```
poc-codeql-artifact-attestation/
├── venv/                   # Virtual environment
├── app.py                  # Flask web application with vulnerabilities
├── utils.py                # Utility functions with security issues
├── database.py             # SQL injection vulnerabilities
├── networking.py           # SSRF and network vulnerabilities
├── config.py              # Configuration vulnerabilities
├── main.py                # Demonstration script
├── requirements.txt       # Vulnerable dependencies
├── exploit_examples.json  # Example attack payloads
├── SECURITY_CHECKLIST.md  # Remediation guide
└── README.md              # This file
```

## Setup Instructions

1. **Activate the virtual environment:**
   ```bash
   source venv/bin/activate
   ```

2. **Install vulnerable dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the demonstration:**
   ```bash
   python main.py
   ```

4. **Run the vulnerable web app:**
   ```bash
   python app.py
   ```

## Vulnerabilities Included

### 1. Injection Vulnerabilities
- **SQL Injection**: Multiple functions in `database.py`
- **Command Injection**: `app.py` ping endpoint
- **Code Injection**: `eval()` and `exec()` usage in `utils.py`
- **LDAP Injection**: Simulated in `app.py`

### 2. Cross-Site Scripting (XSS)
- **Reflected XSS**: Search endpoint in `app.py`
- **Template Injection**: Direct template rendering

### 3. Security Misconfiguration
- **Debug Mode**: Enabled in production
- **Hardcoded Secrets**: Throughout codebase
- **Insecure Dependencies**: Old versions with known CVEs

### 4. Broken Authentication
- **Weak Passwords**: MD5 hashing
- **Predictable Tokens**: Fixed seed random generation
- **Session Fixation**: No proper session management

### 5. Sensitive Data Exposure
- **Information Disclosure**: Debug endpoints
- **Logging Sensitive Data**: Passwords in logs
- **Configuration Exposure**: Secrets in config files

### 6. Broken Access Control
- **Path Traversal**: File reading without validation
- **Insecure Direct Object References**: User ID enumeration
- **Open Redirect**: Unvalidated redirects

### 7. Server-Side Request Forgery (SSRF)
- **Internal Network Access**: Unvalidated URL requests
- **Protocol Smuggling**: Support for various protocols

### 8. Insecure Deserialization
- **Pickle Deserialization**: Unsafe pickle.loads()
- **YAML Unsafe Load**: yaml.load() without safe loader

### 9. Using Components with Known Vulnerabilities
- **Outdated Dependencies**: Specific old versions with CVEs
- **Vulnerable Libraries**: Flask 1.0.2, PyYAML 3.13, etc.

### 10. Insufficient Logging & Monitoring
- **Sensitive Data in Logs**: Passwords and tokens logged
- **No Security Event Monitoring**: Missing security alerts

## Example Exploits

### SQL Injection
```python
# Authentication bypass
username = "admin' OR '1'='1"
password = "anything"

# Data extraction
search_term = "' UNION SELECT credit_card, role FROM users --"
```

### XSS
```javascript
// Reflected XSS in search
http://localhost:5000/search?q=<script>alert('XSS')</script>
```

### Command Injection
```bash
# Ping endpoint
http://localhost:5000/ping?host=localhost; cat /etc/passwd
```

### Path Traversal
```bash
# File read endpoint
http://localhost:5000/file?filename=../../../etc/passwd
```

## Security Testing Tools

This project is ideal for testing with:
- **CodeQL**: Static analysis for security vulnerabilities
- **Bandit**: Python security linter
- **Safety**: Dependency vulnerability scanner
- **OWASP ZAP**: Web application security scanner
- **Burp Suite**: Web vulnerability scanner

## Educational Use Cases

1. **Security Training**: Demonstrate common vulnerabilities
2. **Tool Testing**: Test security scanning tools
3. **Penetration Testing**: Practice exploitation techniques
4. **Code Review**: Learn to identify security issues
5. **DevSecOps**: Integrate security into CI/CD pipelines

## Remediation

See `SECURITY_CHECKLIST.md` for detailed remediation steps for each vulnerability type.

## Legal Disclaimer

This project is for educational and testing purposes only. The vulnerabilities are intentional and should never be deployed in production environments. Users are responsible for ensuring they have proper authorization before testing these vulnerabilities on any systems.

## Dependencies with Known Vulnerabilities

The `requirements.txt` file intentionally includes old versions of packages with known security vulnerabilities:

- **Flask 1.0.2**: CVE-2018-1000656, CVE-2019-1010083
- **Jinja2 2.10**: CVE-2019-10906
- **PyYAML 3.13**: CVE-2017-18342, CVE-2020-1747
- **Requests 2.18.4**: CVE-2018-18074
- **Pillow 5.0.0**: Multiple CVEs
- **lxml 4.2.0**: CVE-2018-19787

## Contributing

This project is designed for educational purposes. If you find additional vulnerability patterns that would be valuable for learning, feel free to contribute while maintaining the educational focus.

---

⚠️ **Remember: This code is intentionally vulnerable. Never use in production!**