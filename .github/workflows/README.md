# Workflow Migration - Old to Unified Approach

This directory contains the migrated workflow files for the unified attestation approach.

## Changes Made

### ✅ New Unified Workflow
- **`unified-build-attest.yml`** - Single workflow that handles:
  - Artifact building
  - CodeQL security scanning  
  - Attestation creation (3 types)
  - Verification

### 📦 Archived Old Workflows
The following workflows have been renamed to `.old` to preserve them but prevent execution:

- **`build-attest.yml.old`** - Old build and basic attestation workflow
- **`release-attest.yml.old`** - Old release workflow with complex timing dependencies
- **`codeql.yml.old`** - Old standalone CodeQL workflow

## Benefits of Unified Approach

### Problems Solved:
- ❌ **Timing Issues**: Old workflows had unreliable coordination
- ❌ **Complexity**: Multiple workflows with dependencies
- ❌ **Data Consistency**: CodeQL results not aligned with artifacts
- ❌ **Verification Complexity**: Multiple attestation formats

### New Benefits:
- ✅ **Reliable Execution**: Single workflow eliminates timing issues
- ✅ **Simpler Maintenance**: One workflow to maintain
- ✅ **Better Data Quality**: CodeQL results match exact artifact
- ✅ **Consistent Attestations**: Predictable format and verification

## Attestation Types Created

The unified workflow creates exactly **3 attestations** per artifact:

1. **SLSA Build Provenance** (`actions/attest-build-provenance@v1`)
   - Standard SLSA build provenance
   - Predicate type: `https://slsa.dev/provenance/v1`

2. **Security Assessment** (`actions/attest@v1`)
   - CodeQL scan results embedded
   - Predicate type: `https://github.com/in-toto/attestation/tree/main/spec/predicates/security-scan`

3. **Vulnerability Disclosure** (`actions/attest@v1`)
   - Educational warnings and intended use
   - Predicate type: `https://slsa.dev/spec/v1.1/provenance`

## Usage

### Triggers
The unified workflow runs on:
- Pull requests to `main`
- Pushes to `main` or `develop`
- Published releases
- Manual workflow dispatch

### Verification
Use the updated verification script:
```bash
./verify-attestations.sh
```

Or verify manually:
```bash
gh attestation verify vulnerable-app-{SHA}.tar.gz --repo eltyagi/poc-codeql-artifact-attestation
```

## Rollback Plan

If you need to rollback to the old approach:
1. Rename `.old` files back to `.yml`
2. Delete or rename `unified-build-attest.yml`
3. Update verification scripts

However, the unified approach is recommended for production use due to its reliability and simplicity.