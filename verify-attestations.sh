#!/bin/bash

# Unified Attestation Verification Script
# This script verifies attestations created by the unified-build-attest.yml workflow

set -e

REPO="eltyagi/poc-codeql-artifact-attestation"
ARTIFACT_PATTERN="vulnerable-app-*.tar.gz"

echo "🔍 Unified Attestation Verification Tool"
echo "========================================"
echo "This script verifies attestations from the simplified unified workflow"
echo ""

# Function to verify a specific artifact
verify_artifact() {
    local artifact_file="$1"
    
    if [ ! -f "$artifact_file" ]; then
        echo "❌ Artifact not found: $artifact_file"
        return 1
    fi
    
    echo ""
    echo "📁 Verifying: $artifact_file"
    echo "-----------------------------------"
    
    # Get file info
    local file_size=$(ls -lh "$artifact_file" | awk '{print $5}')
    local file_hash=$(sha256sum "$artifact_file" | cut -d' ' -f1)
    
    echo "📊 File size: $file_size"
    echo "🔐 SHA256: $file_hash"
    echo ""
    
    # Verify SLSA build provenance
    echo "🏗️  Verifying SLSA build provenance..."
    if gh attestation verify "$artifact_file" --repo "$REPO" 2>/dev/null; then
        echo "✅ SLSA build provenance: VERIFIED"
    else
        echo "❌ SLSA build provenance: FAILED"
    fi
    
    # Verify security assessment attestation
    echo "� Verifying security assessment..."
    if gh attestation verify "$artifact_file" --repo "$REPO" --predicate-type "https://github.com/in-toto/attestation/tree/main/spec/predicates/security-scan" 2>/dev/null; then
        echo "✅ Security assessment: VERIFIED"
    else
        echo "❌ Security assessment: FAILED"
    fi
    
    # Verify vulnerability disclosure attestation
    echo "⚠️  Verifying vulnerability disclosure..."
    if gh attestation verify "$artifact_file" --repo "$REPO" --predicate-type "https://slsa.dev/spec/v1.1/provenance" 2>/dev/null; then
        echo "✅ Vulnerability disclosure: VERIFIED"
    else
        echo "❌ Vulnerability disclosure: FAILED"
    fi
    
    # Verify unified workflow signer
    echo "🔧 Verifying workflow signer..."
    if gh attestation verify "$artifact_file" --repo "$REPO" --signer-workflow ".github/workflows/unified-build-attest.yml" 2>/dev/null; then
        echo "✅ Unified workflow signer: VERIFIED"
    else
        echo "❌ Unified workflow signer: FAILED"
    fi
    
    # Get detailed info
    echo ""
    echo "📋 Detailed attestation info:"
    echo "   Attestations found for this artifact:"
    gh attestation verify "$artifact_file" --repo "$REPO" --format json 2>/dev/null | \
        jq -r '.[] | "  • " + .verificationResult.statement.predicateType + " (workflow: " + (.verificationResult.statement.predicate.runDetails.builder.id // (.verificationResult.statement.predicate.metadata.created_by // "unknown")) + ")"' 2>/dev/null || \
        echo "  Could not retrieve detailed information"
    
    # Extract security summary if available
    echo ""
    echo "🔍 Security scan summary:"
    gh attestation verify "$artifact_file" --repo "$REPO" --format json 2>/dev/null | \
        jq -r '.[] | select(.verificationResult.statement.predicateType == "https://github.com/in-toto/attestation/tree/main/spec/predicates/security-scan") | .verificationResult.statement.predicate.results | "  • Total alerts: " + (.total_alerts | tostring) + " (Critical: " + (.severity_counts.critical | tostring) + ", High: " + (.severity_counts.high | tostring) + ", Medium: " + (.severity_counts.medium | tostring) + ", Low: " + (.severity_counts.low | tostring) + ")"' 2>/dev/null || \
        echo "  No security scan data found in attestations"
    
    echo ""
}

# Main execution
echo "🔍 Looking for artifacts matching: $ARTIFACT_PATTERN"

# Find all matching artifacts
artifacts=($(ls $ARTIFACT_PATTERN 2>/dev/null || true))

if [ ${#artifacts[@]} -eq 0 ]; then
    echo "❌ No artifacts found matching pattern: $ARTIFACT_PATTERN"
    echo ""
    echo "💡 Tips:"
    echo "   - Make sure you're in the repository root directory"
    echo "   - Check if artifacts exist: ls vulnerable-app-*.tar.gz"
    echo "   - Download artifacts from GitHub Actions if needed"
    exit 1
fi

echo "📦 Found ${#artifacts[@]} artifact(s):"
for artifact in "${artifacts[@]}"; do
    echo "   • $artifact"
done

# Verify each artifact
for artifact in "${artifacts[@]}"; do
    verify_artifact "$artifact"
done

echo "🎉 Verification complete!"
echo ""
echo "💡 Usage tips:"
echo "   • Run this script after the unified-build-attest.yml workflow completes"
echo "   • The unified workflow creates 3 attestations: SLSA provenance, security assessment, and vulnerability disclosure"
echo "   • Use 'gh attestation verify --help' for more verification options"
echo "   • Check GitHub Actions logs for detailed attestation creation info"
echo ""
echo "🔗 For more details, see the unified workflow: .github/workflows/unified-build-attest.yml"