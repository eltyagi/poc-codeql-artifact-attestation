# Unified Attestation Verification Guide

This repository implements a simplified software supply chain security system using GitHub's attestation features with a single unified workflow. This guide explains how to verify that attestations are created correctly.

## Overview

The repository uses **one unified workflow** that creates three types of attestations in a single, reliable process:

1. **SLSA Build Provenance** - Standard build provenance attestation
2. **Security Assessment** - CodeQL vulnerability scan results embedded in attestation  
3. **Vulnerability Disclosure** - Educational purpose and vulnerability warnings

## Key Benefits of the Unified Approach

✅ **Reliable timing** - Everything happens in sequence in one job  
✅ **Simpler coordination** - No workflow dependencies or timing issues  
✅ **Better data consistency** - CodeQL results are fresh and matched to exact artifact  
✅ **Easier verification** - Predictable attestation types  
✅ **Atomic operations** - Build + security scan + attestation happen together

## Quick Verification

### Using the Verification Script

Run the provided script to verify all attestations:

```bash
./verify-attestations.sh
```

### Manual Verification Commands

#### 1. Basic Attestation Verification
```bash
# Verify all attestations for an artifact
gh attestation verify vulnerable-app-{SHA}.tar.gz \
  --repo eltyagi/poc-codeql-artifact-attestation

# Verify SLSA build provenance specifically
gh attestation verify vulnerable-app-{SHA}.tar.gz \
  --repo eltyagi/poc-codeql-artifact-attestation \
  --signer-workflow ".github/workflows/unified-build-attest.yml"
```

#### 2. Security Assessment Verification
```bash
# Verify security scan attestation
gh attestation verify vulnerable-app-{SHA}.tar.gz \
  --repo eltyagi/poc-codeql-artifact-attestation \
  --predicate-type "https://github.com/in-toto/attestation/tree/main/spec/predicates/security-scan"
```

#### 3. Vulnerability Disclosure Verification
```bash
# Verify vulnerability disclosure attestation
gh attestation verify vulnerable-app-{SHA}.tar.gz \
  --repo eltyagi/poc-codeql-artifact-attestation \
  --predicate-type "https://slsa.dev/spec/v1.1/provenance"
```

#### 4. Detailed Attestation Information
```bash
gh attestation verify vulnerable-app-{SHA}.tar.gz \
  --repo eltyagi/poc-codeql-artifact-attestation \
  --format json | jq '.[] | {
    predicate_type: .verificationResult.statement.predicateType,
    workflow: (.verificationResult.statement.predicate.metadata.created_by // "unknown"),
    subject: .verificationResult.statement.subject[0],
    security_summary: .verificationResult.statement.predicate.results // null
  }'
```

#### 5. Extract Security Scan Results
```bash
gh attestation verify vulnerable-app-{SHA}.tar.gz \
  --repo eltyagi/poc-codeql-artifact-attestation \
  --format json | jq '.[] | 
  select(.verificationResult.statement.predicateType == "https://github.com/in-toto/attestation/tree/main/spec/predicates/security-scan") | 
  .verificationResult.statement.predicate.results'
```

## Workflow Integration

### Unified Workflow (`unified-build-attest.yml`)
- **Triggers**: PR, push to main/develop, releases, manual dispatch
- **Process**: Build → CodeQL Scan → Extract Results → Create Attestations
- **Creates**: SLSA provenance + security assessment + vulnerability disclosure attestations
- **Artifacts**: `vulnerable-app-{SHA}.tar.gz`

**Workflow Steps:**
1. Build artifact package
2. Initialize and run CodeQL analysis
3. Extract security results from CodeQL API
4. Create SLSA build provenance attestation
5. Create security assessment attestation (with CodeQL data)
6. Create vulnerability disclosure attestation 
7. Verify all attestations were created successfully

### Legacy Workflows (Deprecated)
The old multi-workflow approach has been replaced with the unified workflow:
- ~~`build-attest.yml`~~ → Replaced by `unified-build-attest.yml`
- ~~`release-attest.yml`~~ → Functionality merged into unified workflow  
- ~~`codeql.yml`~~ → CodeQL analysis integrated into unified workflow

## Verification Checklist

### ✅ What to Verify

1. **Artifact Integrity**
   - File exists and has correct SHA256
   - Matches expected artifact from workflow

2. **SLSA Build Provenance** 
   - Signed by unified workflow
   - Contains accurate build metadata
   - References correct commit SHA

3. **Security Assessment**
   - CodeQL scan results embedded in attestation
   - Vulnerability counts by severity
   - Scan timestamp and context

4. **Vulnerability Disclosure**
   - Educational purpose warnings
   - Intended use documentation
   - Security summary data

4. **Workflow Identity**
   - Certificate matches repository
   - Signer workflow is expected
   - OIDC issuer is GitHub

### ❌ Common Issues and Fixes

#### Issue: "No attestations found"
**Cause**: Artifact name mismatch or unified workflow hasn't completed
**Fix**: 
- Check artifact naming: `vulnerable-app-{full-commit-sha}.tar.gz`
- Verify unified workflow completed successfully
- Check artifact exists in GitHub Actions
- Run: `./verify-attestations.sh` to check all artifacts

#### Issue: "Verification failed"
**Cause**: Attestation predicate type mismatch or workflow signer mismatch
**Fix**:
- Use correct predicate type for verification
- Verify workflow signer is `unified-build-attest.yml`
- Check if attestation was created with different predicate type

#### Issue: "Certificate validation failed" 
**Cause**: Repository or workflow mismatch
**Fix**:
- Verify `--repo` flag matches attestation source
- Check `--signer-workflow` path: `.github/workflows/unified-build-attest.yml`
- Ensure you have proper access to the repository

## Advanced Verification

### Policy Enforcement Example
```bash
# Verify and enforce that security scan attestation exists
gh attestation verify artifact.tar.gz \
  --repo eltyagi/poc-codeql-artifact-attestation \
  --format json | jq -e '.[] | 
  select(.verificationResult.statement.predicateType == "https://github.com/in-toto/attestation/tree/main/spec/predicates/security-scan") |
  select(.verificationResult.statement.predicate.metadata.created_by == "unified-build-attest.yml")'
```

### Extract Security Metrics
```bash
# Get security summary from attestations
gh attestation verify artifact.tar.gz \
  --repo eltyagi/poc-codeql-artifact-attestation \
  --format json | jq '.[] | 
  select(.verificationResult.statement.predicateType | contains("security-scan")) |
  .verificationResult.statement.predicate.results | 
  "Total alerts: \(.total_alerts), Critical: \(.severity_counts.critical), High: \(.severity_counts.high)"'
```

### Batch Verification
```bash
# Verify all artifacts in directory
for artifact in vulnerable-app-*.tar.gz; do
  echo "Verifying: $artifact"
  gh attestation verify "$artifact" --repo eltyagi/poc-codeql-artifact-attestation
done
```

## Monitoring and Automation

### GitHub Actions Integration
The unified workflow automatically verifies attestations after creation:
- Single workflow creates and verifies all attestation types
- Logs provide detailed verification results
- Step summary shows security scan results and attestation status

### CI/CD Pipeline Integration
```yaml
- name: Verify Supply Chain Security
  run: |
    # Download artifact
    gh run download ${{ github.run_id }} -n vulnerable-app-source
    
    # Verify all attestations created by unified workflow
    gh attestation verify vulnerable-app-*.tar.gz \
      --repo ${{ github.repository }} \
      --signer-workflow ".github/workflows/unified-build-attest.yml"
    
    # Extract and validate security metrics
    gh attestation verify vulnerable-app-*.tar.gz \
      --repo ${{ github.repository }} \
      --format json | jq '.[] | select(.verificationResult.statement.predicateType | contains("security-scan")) | .verificationResult.statement.predicate.results'
```

## Troubleshooting

### Debug Commands
```bash
# Check workflow runs
gh run list --repo eltyagi/poc-codeql-artifact-attestation

# View specific run
gh run view RUN_ID --repo eltyagi/poc-codeql-artifact-attestation

# List artifacts
gh api repos/eltyagi/poc-codeql-artifact-attestation/actions/artifacts
```

### Logs and Evidence
- **Workflow logs**: Check GitHub Actions tab for detailed execution logs
- **Attestation content**: Use `--format json` to inspect full attestation data
- **Certificate details**: Examine `signature.certificate` in JSON output

## Security Considerations

1. **Trust Boundaries**: Only trust attestations from expected workflows
2. **Predicate Validation**: Verify predicate type matches expected claim
3. **Timestamp Verification**: Check `verifiedTimestamps` for attestation age
4. **Repository Identity**: Ensure certificate matches expected repository

## Additional Resources

- [GitHub Attestations Documentation](https://docs.github.com/en/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds)
- [SLSA Provenance Specification](https://slsa.dev/provenance/)
- [in-toto Attestation Framework](https://in-toto.io/)
- [Sigstore Documentation](https://docs.sigstore.dev/)