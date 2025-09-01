#!/bin/bash

# Attestation Verification Script
# This script helps verify attestations for artifacts in the repository

set -e

REPO="eltyagi/poc-codeql-artifact-attestation"
ARTIFACT_PATTERN="vulnerable-app-*.tar.gz"

echo "🔍 Attestation Verification Tool"
echo "================================="

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
    
    # Verify build provenance
    echo "🏗️  Verifying build provenance..."
    if gh attestation verify "$artifact_file" --repo "$REPO" 2>/dev/null; then
        echo "✅ Build provenance: VERIFIED"
    else
        echo "❌ Build provenance: FAILED"
    fi
    
    # Verify security notices
    echo "🛡️  Verifying security notices..."
    if gh attestation verify "$artifact_file" --repo "$REPO" --predicate-type "https://slsa.dev/spec/v1.1/provenance" 2>/dev/null; then
        echo "✅ Security notices: VERIFIED"
    else
        echo "❌ Security notices: FAILED"
    fi
    
    # Verify release attestations
    echo "🚀 Verifying release attestations..."
    if gh attestation verify "$artifact_file" --repo "$REPO" --signer-workflow ".github/workflows/release-attest.yml" 2>/dev/null; then
        echo "✅ Release attestations: VERIFIED"
    else
        echo "❌ Release attestations: FAILED"
    fi
    
    # Get detailed info
    echo ""
    echo "📋 Detailed attestation info:"
    gh attestation verify "$artifact_file" --repo "$REPO" --format json 2>/dev/null | \
        jq -r '.[] | "  • " + .verificationResult.statement.predicateType + " (signed by: " + (.verificationResult.statement.predicate.runDetails.builder.id // "unknown") + ")"' 2>/dev/null || \
        echo "  Could not retrieve detailed information"
    
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
echo "   • Run this script regularly to check attestation integrity"
echo "   • Use 'gh attestation verify --help' for more options"
echo "   • Check workflow logs for attestation creation details"