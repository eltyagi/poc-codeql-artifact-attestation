# CodeQL Artifact Attestation Workflow

This repository demonstrates a complete GitHub Actions workflow that creates artifact attestations enriched with CodeQL security scan results.

## Workflow Overview

The workflow (`/.github/workflows/attestation.yml`) consists of three main jobs:

### 1. Build Job 🔨
- Builds a Python package from the source code
- Generates SHA256 hash of the artifact
- Uploads the package as a workflow artifact

### 2. CodeQL Scan Job 🔍
- Initializes CodeQL for Python analysis
- Runs security scanning with `security-and-quality` query suite
- Generates SARIF results and uploads to GitHub
- Saves SARIF files as workflow artifacts

### 3. Attestation Job 📋
- Downloads build artifacts and SARIF results
- Extracts PR information and CodeQL findings
- Creates custom attestation predicate with:
  - Artifact metadata (name, hash, timestamp)
  - Pull request details (author, merge commit, etc.)
  - CodeQL scan results (vulnerabilities, alerts summary)
  - Build environment information
- Generates cryptographically signed attestation

## Workflow Triggers

The workflow runs on:
- Push to `main` or `develop` branches
- Pull request closures to `main` branch

## Required Permissions

```yaml
permissions:
  contents: read        # Read repository contents
  security-events: read # Access CodeQL results
  attestations: write   # Create attestations
  id-token: write      # OIDC token for signing
  actions: read        # Access workflow data
```

## Attestation Predicate Schema

The custom predicate includes:

```json
{
  "predicateType": "https://github.com/attestations/codeql-scan/v1",
  "predicate": {
    "artifact": {
      "name": "package.tar.gz",
      "digest": "sha256:...",
      "buildTimestamp": "2025-09-10T..."
    },
    "pullRequest": {
      "number": 123,
      "author": "username",
      "mergeCommit": "abc123..."
    },
    "codeqlScan": {
      "sarif_results": [...],
      "alertsSummary": {...},
      "resultCount": 15
    }
  }
}
```

## Supporting Scripts

### `/scripts/parse_sarif.py`
- Parses SARIF files from CodeQL analysis
- Extracts vulnerability details and metadata
- Generates summary statistics

### `/scripts/build_predicate.py`  
- Combines artifact, PR, and CodeQL data
- Builds the custom attestation predicate
- Interfaces with GitHub API for alert information

## Intentional Vulnerabilities

This repository contains intentional security vulnerabilities for testing:
- SQL injection in `database.py`
- XSS vulnerabilities in `app.py`  
- Command injection in network utilities
- Insecure dependencies in `requirements.txt`

⚠️ **Warning**: This code is for educational/testing purposes only!

## Example Usage

1. **Enable CodeQL**: Ensure CodeQL is enabled in repository settings
2. **Create PR**: Make changes and create a pull request
3. **Merge PR**: The workflow triggers on PR merge to main
4. **View Results**: Check the Actions tab for attestation creation

## Verifying Attestations

Attestations can be verified using:
- GitHub's native attestation verification
- `gh` CLI with attestation commands
- Custom verification scripts

## Benefits

✅ **Supply Chain Security**: Links artifacts to exact source and scan results  
✅ **Audit Trail**: Complete record of what was scanned and when  
✅ **Compliance**: Meets software supply chain security requirements  
✅ **Transparency**: All security findings are embedded in the attestation  
✅ **Tamper Evidence**: Cryptographic signatures prevent modification

## Repository Structure

```
.github/workflows/
├── attestation.yml          # Main workflow
scripts/
├── parse_sarif.py           # SARIF parser
└── build_predicate.py       # Predicate builder
*.py                         # Vulnerable Python code
pyproject.toml              # Package configuration
requirements.txt            # Vulnerable dependencies
```