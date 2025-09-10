# CodeQL Artifact Attestation - Proof of Concept

🔐 **Supply Chain Security with CodeQL Integration**

This repository demonstrates a complete **GitHub Actions workflow** that creates **cryptographically signed artifact attestations** enriched with **CodeQL security scan results**. It provides a tamper-evident audit trail linking software artifacts to their source code, build process, and security analysis.

⚠️ **Note: This project contains intentional security vulnerabilities for testing and educational purposes!**

## 🚀 What This Does

Creates **artifact attestations** that include:
- ✅ **Build Provenance** - Who built it, when, and how
- ✅ **CodeQL Scan Results** - Security vulnerabilities found
- ✅ **Pull Request Context** - Which PR introduced changes
- ✅ **Complete Audit Trail** - Immutable record of the entire process

## 🔄 Workflow Overview

The workflow (`.github/workflows/attestation.yml`) runs automatically on:
- Push to `main` or `develop` branches
- Pull request merges to `main`

### Three-Stage Process:

```
┌─────────────┐    ┌──────────────┐    ┌─────────────────┐
│   Build     │───▶│  CodeQL      │───▶│   Attestation   │
│   Package   │    │  Scan        │    │   Creation      │
└─────────────┘    └──────────────┘    └─────────────────┘
```

### 1. **Build Stage** 🔨
- Builds Python package from source
- Generates cryptographic hash (SHA256)
- Uploads artifacts for later stages

### 2. **CodeQL Security Scan** 🔍
- Runs CodeQL analysis with `security-and-quality` queries
- Generates SARIF results with vulnerability details
- Uploads results to GitHub Security tab
- Saves scan data for attestation

### 3. **Attestation Creation** 📋
- Combines build info + CodeQL results + PR metadata
- Creates custom attestation predicate
- Generates cryptographically signed attestation
- Links everything together immutably

## 📊 Attestation Schema

The custom attestation includes:

```json
{
  "predicateType": "https://github.com/attestations/codeql-scan/v1",
  "predicate": {
    "artifact": {
      "name": "poc_codeql_artifact_attestation-1.0.0.tar.gz",
      "digest": "sha256:abc123...",
      "buildTimestamp": "2025-09-10T14:30:00Z"
    },
    "pullRequest": {
      "number": 42,
      "author": "developer",
      "mergeCommit": "def456...",
      "mergedAt": "2025-09-10T14:35:00Z"
    },
    "codeqlScan": {
      "resultCount": 15,
      "sarif_results": [...],
      "alertsSummary": {
        "total": 20,
        "open": 5,
        "fixed": 3,
        "by_severity": {"high": 2, "medium": 8, "low": 5}
      }
    }
  }
}
```

## 🛠️ Setup & Usage

### Prerequisites
- GitHub repository with CodeQL enabled
- Python project with `pyproject.toml`
- Required workflow permissions (automatically configured)

### Quick Start
1. **Copy the workflow** from `.github/workflows/attestation.yml` to your repository
2. **Ensure CodeQL is enabled** in repository settings → Security → Code scanning
3. **Create a PR or push** to `main`/`develop` to trigger the workflow
4. **View results** in the Actions tab and Security tab

### Verifying Attestations
Use GitHub CLI to verify attestations:
```bash
gh attestation verify artifact.tar.gz --repo owner/repository
```

## 📁 Project Structure

```
poc-codeql-artifact-attestation/
├── .github/workflows/
│   └── attestation.yml          # Main CodeQL attestation workflow
├── scripts/
│   ├── parse_sarif.py           # SARIF parser utility
│   └── build_predicate.py       # Attestation predicate builder
├── app.py                       # Flask app with vulnerabilities
├── database.py                  # SQL injection examples
├── networking.py                # SSRF vulnerabilities
├── main.py                      # Demo script
├── pyproject.toml              # Package configuration
├── requirements.txt            # Vulnerable dependencies
└── WORKFLOW_GUIDE.md           # Detailed workflow documentation
```

## 🔐 Security Benefits

✅ **Supply Chain Security** - Links artifacts to exact source and scan results  
✅ **Audit Trail** - Complete record of what was scanned and when  
✅ **Compliance** - Meets software supply chain security requirements  
✅ **Transparency** - All security findings embedded in attestation  
✅ **Tamper Evidence** - Cryptographic signatures prevent modification  
✅ **Automated** - No manual intervention required
## 🧪 Educational Vulnerability Testing

This repository contains **intentional security vulnerabilities** perfect for testing the CodeQL workflow:

### Vulnerability Categories Included

### 1. **Injection Vulnerabilities**
- **SQL Injection**: Multiple functions in `database.py`
- **Command Injection**: `app.py` ping endpoint
- **Code Injection**: `eval()` and `exec()` usage in `utils.py`
- **LDAP Injection**: Simulated in `app.py`

### 2. **Cross-Site Scripting (XSS)**
- **Reflected XSS**: Search endpoint in `app.py`
- **Template Injection**: Direct template rendering

### 3. **Security Misconfiguration**
- **Debug Mode**: Enabled in production
- **Hardcoded Secrets**: Throughout codebase
- **Insecure Dependencies**: Old versions with known CVEs

### 4. **Broken Authentication**
- **Weak Passwords**: MD5 hashing
- **Predictable Tokens**: Fixed seed random generation
- **Session Fixation**: No proper session management

### 5. **Sensitive Data Exposure**
- **Information Disclosure**: Debug endpoints
- **Logging Sensitive Data**: Passwords in logs
- **Configuration Exposure**: Secrets in config files

### 6. **Broken Access Control**
- **Path Traversal**: File reading without validation
- **Insecure Direct Object References**: User ID enumeration
- **Open Redirect**: Unvalidated redirects

### 7. **Server-Side Request Forgery (SSRF)**
- **Internal Network Access**: Unvalidated URL requests
- **Protocol Smuggling**: Support for various protocols

### 8. **Insecure Deserialization**
- **Pickle Deserialization**: Unsafe pickle.loads()
- **YAML Unsafe Load**: yaml.load() without safe loader

### 9. **Using Components with Known Vulnerabilities**
- **Outdated Dependencies**: Specific old versions with CVEs
- **Vulnerable Libraries**: Flask 1.0.2, PyYAML 3.13, etc.

### 10. **Insufficient Logging & Monitoring**
- **Sensitive Data in Logs**: Passwords and tokens logged
- **No Security Event Monitoring**: Missing security alerts

## 🎯 Testing the Workflow

### Running the Vulnerable Application
1. **Set up environment:**
   ```bash
   python -m pip install -r requirements.txt
   ```

2. **Run the vulnerable web app:**
   ```bash
   python app.py
   ```

3. **Run demo exploits:**
   ```bash
   python main.py
   ```

### Example Security Issues CodeQL Will Detect

**SQL Injection:**
```python
# In database.py - CodeQL will flag this
cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")
```

**Command Injection:**
```python
# In app.py - CodeQL will detect this
os.system(f"ping -c 1 {host}")
```

**XSS Vulnerability:**
```python
# In app.py - CodeQL will identify this
return f"<h1>Search results for: {query}</h1>"
```

### Workflow Testing Process
1. **Make changes** to the vulnerable code
2. **Create a pull request** 
3. **Watch the workflow** run CodeQL analysis
4. **Review the attestation** with embedded security findings
5. **See results** in GitHub Security tab

## 🔧 Development & Testing Tools

This project works great with:
- **CodeQL** - Static analysis (primary focus)
- **Bandit** - Python security linter  
- **Safety** - Dependency vulnerability scanner
- **OWASP ZAP** - Web application scanner
- **Burp Suite** - Manual security testing

## ⚖️ Legal Disclaimer

⚠️ **EDUCATIONAL USE ONLY**: This code contains intentional vulnerabilities and should never be deployed in production. Users are responsible for ensuring proper authorization before testing vulnerabilities.

## 📈 Workflow Outputs

When the workflow completes successfully, you'll see:

### 1. **GitHub Security Tab**
- CodeQL scan results with detailed findings
- Alert timeline and status tracking
- SARIF file uploads with vulnerability details

### 2. **Actions Artifacts**
- `python-package` - Built software artifact
- `codeql-sarif` - Raw SARIF scan results
- `attestation-data` - Custom CodeQL predicate JSON

### 3. **Attestations**
- **Build Provenance** - GitHub's native attestation
- **Custom CodeQL Data** - Embedded in workflow artifacts
- Cryptographic signatures linking everything together

### 4. **Workflow Summary**
```
🔒 Artifact Attestation Created
Artifact: poc_codeql_artifact_attestation-1.0.0.tar.gz
Hash: sha256:abc123...
CodeQL Scan: ✅ Completed  
Build Provenance: ✅ Generated and signed
Custom CodeQL Data: ✅ Saved to artifacts
```

## 🔍 Real-World Applications

This workflow pattern is valuable for:

- **Enterprise Software** - Compliance and audit requirements
- **Open Source Projects** - Transparency and trust building  
- **CI/CD Pipelines** - Automated security verification
- **Supply Chain Security** - SLSA compliance
- **Regulatory Requirements** - SOX, GDPR, HIPAA compliance
- **Security Research** - Vulnerability analysis and tracking

## 🤝 Contributing

This is a proof-of-concept project. Contributions welcome for:
- Additional vulnerability examples
- Workflow improvements  
- Documentation enhancements
- Language-specific adaptations

## 📚 Additional Resources

- **Detailed Workflow Guide**: See `WORKFLOW_GUIDE.md`
- **GitHub Attestations**: [Official Documentation](https://docs.github.com/en/actions/security-guides/using-artifact-attestations)
- **CodeQL Documentation**: [Getting Started](https://codeql.github.com/docs/)
- **SLSA Framework**: [Supply Chain Security](https://slsa.dev/)

---

🔐 **Ready to implement supply chain security with CodeQL integration!**