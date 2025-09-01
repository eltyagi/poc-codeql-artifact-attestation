# Attestation Verification Guide

This repository implements a comprehensive software supply chain security system using GitHub's attestation features. This guide explains how to verify that attestations are created correctly.

## Overview

The repository creates three types of attestations:

1. **Build Provenance** - Proves how artifacts were built
2. **Security Assessments** - CodeQL vulnerability scan results  
3. **Release Attestations** - Complete release pipeline verification

## Quick Verification

### Using the Verification Script

Run the provided script to verify all attestations:

```bash
./verify-attestations.sh
```

### Manual Verification Commands

#### 1. Basic Attestation Verification
```bash
# Verify build provenance (most common)
gh attestation verify vulnerable-app-{SHA}.tar.gz \
  --repo eltyagi/poc-codeql-artifact-attestation

# Verify with specific workflow
gh attestation verify vulnerable-app-{SHA}.tar.gz \
  --repo eltyagi/poc-codeql-artifact-attestation \
  --signer-workflow ".github/workflows/build-attest.yml"
```

#### 2. Security Notice Verification
```bash
gh attestation verify vulnerable-app-{SHA}.tar.gz \
  --repo eltyagi/poc-codeql-artifact-attestation \
  --predicate-type "https://slsa.dev/spec/v1.1/provenance"
```

#### 3. Detailed Attestation Information
```bash
gh attestation verify vulnerable-app-{SHA}.tar.gz \
  --repo eltyagi/poc-codeql-artifact-attestation \
  --format json | jq '.[] | {
    predicate_type: .verificationResult.statement.predicateType,
    signer: .verificationResult.statement.predicate.runDetails.builder.id,
    subject: .verificationResult.statement.subject[0]
  }'
```

## Workflow Integration

### Build Workflow (`build-attest.yml`)
- **Triggers**: PR, push to main, releases
- **Creates**: Build provenance + security notice attestations
- **Artifacts**: `vulnerable-app-{SHA}.tar.gz`

### Release Workflow (`release-attest.yml`)
- **Triggers**: Push to main, published releases
- **Creates**: Security assessment + release provenance attestations
- **Verifies**: All existing attestations

### CodeQL Workflow (`codeql.yml`)
- **Triggers**: Push/PR, scheduled scans
- **Creates**: Vulnerability scan attestations
- **Languages**: Python, GitHub Actions

## Verification Checklist

### ✅ What to Verify

1. **Artifact Integrity**
   - File exists and has correct SHA256
   - Matches expected artifact from workflow

2. **Build Provenance** 
   - Signed by correct workflow
   - Contains accurate build metadata
   - References correct commit SHA

3. **Security Assessments**
   - CodeQL scan results present
   - Vulnerability data is current
   - Scan covers all languages

4. **Workflow Identity**
   - Certificate matches repository
   - Signer workflow is expected
   - OIDC issuer is GitHub

### ❌ Common Issues and Fixes

#### Issue: "No attestations found"
**Cause**: Artifact name mismatch or attestations not created
**Fix**: 
- Check artifact naming: `vulnerable-app-{full-commit-sha}.tar.gz`
- Verify workflow completed successfully
- Check artifact exists in GitHub Actions

#### Issue: "Verification failed"
**Cause**: Attestation predicate type mismatch
**Fix**:
- Use correct predicate type for verification
- Check if attestation was created with different predicate

#### Issue: "Certificate validation failed" 
**Cause**: Repository or workflow mismatch
**Fix**:
- Verify `--repo` flag matches attestation source
- Check `--signer-workflow` path is correct

## Advanced Verification

### Policy Enforcement Example
```bash
# Verify and enforce policy
gh attestation verify artifact.tar.gz \
  --repo eltyagi/poc-codeql-artifact-attestation \
  --format json | jq -e '.[] | 
  select(.verificationResult.statement.predicateType == "https://slsa.dev/provenance/v1") |
  select(.verificationResult.statement.predicate.runDetails.builder.id | contains("build-attest.yml"))'
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
The workflows automatically verify attestations after creation:
- Build workflow creates and verifies build attestations
- Release workflow verifies all attestation types
- Logs provide detailed verification results

### CI/CD Pipeline Integration
```yaml
- name: Verify Supply Chain Security
  run: |
    # Download artifact
    gh run download ${{ github.run_id }} -n vulnerable-app-source
    
    # Verify attestations
    gh attestation verify vulnerable-app-*.tar.gz \
      --repo ${{ github.repository }} \
      --signer-workflow ".github/workflows/build-attest.yml"
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