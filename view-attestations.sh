#!/bin/bash

# Attestation Viewer Script for CodeQL Artifact Attestation PoC
# This script helps you view and analyze the attestation data we created

set -e

REPO="eltyagi/poc-codeql-artifact-attestation"
ARTIFACT_PATTERN="vulnerable-app-*.tar.gz"

echo "🔍 Attestation Data Viewer"
echo "=========================="
echo

# Function to display help
show_help() {
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  -h, --help          Show this help message"
    echo "  -l, --list          List available artifacts"
    echo "  -v, --verify FILE   Verify attestations for specific file"
    echo "  -d, --details FILE  Show detailed attestation data"
    echo "  -a, --all FILE      Show all attestation types for file"
    echo "  -s, --summary       Show summary of all attestations"
    echo
    echo "Examples:"
    echo "  $0 --list"
    echo "  $0 --verify vulnerable-app-abc123.tar.gz"
    echo "  $0 --details vulnerable-app-abc123.tar.gz"
    echo "  $0 --all vulnerable-app-abc123.tar.gz"
}

# Function to list available artifacts
list_artifacts() {
    echo "📁 Available artifacts:"
    if ls $ARTIFACT_PATTERN >/dev/null 2>&1; then
        for file in $ARTIFACT_PATTERN; do
            if [ -f "$file" ]; then
                echo "  - $file"
                echo "    Size: $(ls -lh "$file" | awk '{print $5}')"
                echo "    SHA256: $(shasum -a 256 "$file" | cut -d' ' -f1)"
                echo
            fi
        done
    else
        echo "  No local artifacts found matching pattern: $ARTIFACT_PATTERN"
        echo "  Note: Artifacts may be available remotely on GitHub"
    fi
}

# Function to verify attestations
verify_attestations() {
    local file="$1"
    echo "🔐 Verifying attestations for: $file"
    echo
    
    if [ ! -f "$file" ]; then
        echo "❌ File not found locally: $file"
        echo "Try downloading it first or use the GitHub API"
        return 1
    fi
    
    echo "📊 SLSA Build Provenance:"
    if gh attestation verify "$file" --repo "$REPO" 2>/dev/null; then
        echo "✅ SLSA build provenance: VERIFIED"
    else
        echo "⚠️  SLSA build provenance: Could not verify or not found"
    fi
    echo
    
    echo "🔍 Security Assessment:"
    if gh attestation verify "$file" --repo "$REPO" --predicate-type "https://github.com/in-toto/attestation/tree/main/spec/predicates/security-scan" 2>/dev/null; then
        echo "✅ Security assessment: VERIFIED"
    else
        echo "⚠️  Security assessment: Could not verify or not found"
    fi
    echo
    
    echo "⚠️  Vulnerability Disclosure:"
    if gh attestation verify "$file" --repo "$REPO" --predicate-type "https://slsa.dev/spec/v1.1/provenance" 2>/dev/null; then
        echo "✅ Vulnerability disclosure: VERIFIED"
    else
        echo "⚠️  Vulnerability disclosure: Could not verify or not found"
    fi
}

# Function to show detailed attestation data
show_details() {
    local file="$1"
    echo "📋 Detailed attestation data for: $file"
    echo
    
    if [ ! -f "$file" ]; then
        echo "❌ File not found locally: $file"
        return 1
    fi
    
    echo "🔍 Getting attestation data..."
    
    # Get all attestations with JSON output
    local temp_file=$(mktemp)
    if gh attestation verify "$file" --repo "$REPO" --format json > "$temp_file" 2>/dev/null; then
        echo "📄 Raw attestation data saved to: $temp_file"
        echo
        
        # Extract and display key information
        echo "🏷️  Attestation Summary:"
        jq -r '.[] | "- Type: " + .verificationResult.statement.predicateType' "$temp_file" 2>/dev/null || echo "Could not parse attestation types"
        
        echo
        echo "🔧 Build Information:"
        jq -r '.[] | .verificationResult.statement.predicate.buildDefinition.externalParameters.workflow.repository // "N/A"' "$temp_file" 2>/dev/null | head -1 | sed 's/^/  Repository: /'
        jq -r '.[] | .verificationResult.statement.predicate.buildDefinition.externalParameters.workflow.ref // "N/A"' "$temp_file" 2>/dev/null | head -1 | sed 's/^/  Ref: /'
        
        echo
        echo "📁 Subject Information:"
        jq -r '.[] | .verificationResult.statement.subject[0].name // "N/A"' "$temp_file" 2>/dev/null | head -1 | sed 's/^/  Name: /'
        jq -r '.[] | .verificationResult.statement.subject[0].digest.sha256 // "N/A"' "$temp_file" 2>/dev/null | head -1 | sed 's/^/  SHA256: /'
        
        echo
        echo "💾 For full JSON data, examine: $temp_file"
        echo "   You can use: jq '.' $temp_file | less"
        
    else
        echo "❌ Could not retrieve attestation data"
        rm -f "$temp_file"
        return 1
    fi
}

# Function to show all attestation types
show_all_attestations() {
    local file="$1"
    echo "🎯 All attestation types for: $file"
    echo
    
    if [ ! -f "$file" ]; then
        echo "❌ File not found locally: $file"
        return 1
    fi
    
    # Try different predicate types
    local predicate_types=(
        "https://slsa.dev/provenance/v1"
        "https://github.com/in-toto/attestation/tree/main/spec/predicates/security-scan"
        "https://slsa.dev/spec/v1.1/provenance"
    )
    
    local type_names=(
        "SLSA Build Provenance"
        "Security Assessment"
        "Vulnerability Disclosure"
    )
    
    for i in "${!predicate_types[@]}"; do
        local predicate_type="${predicate_types[$i]}"
        local type_name="${type_names[$i]}"
        
        echo "🔍 Checking: $type_name"
        echo "   Predicate Type: $predicate_type"
        
        if gh attestation verify "$file" --repo "$REPO" --predicate-type "$predicate_type" --format json >/dev/null 2>&1; then
            echo "   Status: ✅ VERIFIED"
            
            # Extract custom predicate data if available
            local temp_file=$(mktemp)
            gh attestation verify "$file" --repo "$REPO" --predicate-type "$predicate_type" --format json > "$temp_file" 2>/dev/null
            
            case "$type_name" in
                "Security Assessment")
                    echo "   📊 Security Data:"
                    # Look for our custom security data
                    jq -r '.[] | .verificationResult.statement.predicate.results.total_alerts // "N/A"' "$temp_file" 2>/dev/null | sed 's/^/     Total Alerts: /'
                    ;;
                "Vulnerability Disclosure")
                    echo "   ⚠️  Vulnerability Info:"
                    # Look for our custom vulnerability data
                    jq -r '.[] | .verificationResult.statement.predicate.notice // "N/A"' "$temp_file" 2>/dev/null | sed 's/^/     Notice: /'
                    ;;
            esac
            
            rm -f "$temp_file"
        else
            echo "   Status: ❌ NOT FOUND"
        fi
        echo
    done
}

# Function to show summary
show_summary() {
    echo "📊 Attestation Summary"
    echo "====================="
    echo
    
    echo "🏗️  Repository: $REPO"
    echo "🔍 Pattern: $ARTIFACT_PATTERN"
    echo
    
    echo "📁 Local Artifacts:"
    list_artifacts
    
    echo "🌐 Remote Attestations:"
    echo "   Use GitHub's web interface:"
    echo "   https://github.com/$REPO/security/advisories"
    echo "   https://github.com/$REPO/security"
    echo
    
    echo "🔧 Commands to explore:"
    echo "   gh attestation verify <file> --repo $REPO"
    echo "   gh attestation verify <file> --repo $REPO --format json"
    echo "   gh api repos/$REPO/attestations"
}

# Main script logic
case "${1:-}" in
    -h|--help)
        show_help
        ;;
    -l|--list)
        list_artifacts
        ;;
    -v|--verify)
        if [ -z "${2:-}" ]; then
            echo "❌ Error: Please specify a file to verify"
            echo "Usage: $0 --verify <filename>"
            exit 1
        fi
        verify_attestations "$2"
        ;;
    -d|--details)
        if [ -z "${2:-}" ]; then
            echo "❌ Error: Please specify a file for details"
            echo "Usage: $0 --details <filename>"
            exit 1
        fi
        show_details "$2"
        ;;
    -a|--all)
        if [ -z "${2:-}" ]; then
            echo "❌ Error: Please specify a file for all attestations"
            echo "Usage: $0 --all <filename>"
            exit 1
        fi
        show_all_attestations "$2"
        ;;
    -s|--summary|"")
        show_summary
        ;;
    *)
        echo "❌ Error: Unknown option: $1"
        echo
        show_help
        exit 1
        ;;
esac