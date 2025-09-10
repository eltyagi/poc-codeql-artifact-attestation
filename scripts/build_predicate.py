#!/usr/bin/env python3
"""
Attestation Predicate Builder
Combines artifact information, PR details, and CodeQL scan results
into a custom attestation predicate for supply chain security.
"""

import json
import os
import requests
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List


class AttestationPredicateBuilder:
    """Builds custom attestation predicates for artifacts with CodeQL data."""
    
    def __init__(self, github_token: Optional[str] = None):
        self.github_token = github_token or os.environ.get('GITHUB_TOKEN')
        self.github_repo = os.environ.get('GITHUB_REPOSITORY')
        self.github_headers = {
            'Authorization': f'token {self.github_token}',
            'Accept': 'application/vnd.github.v3+json'
        } if self.github_token else {}
    
    def build_predicate(self, 
                       artifact_path: str,
                       sarif_results_file: Optional[str] = None) -> Dict[str, Any]:
        """Build the complete attestation predicate."""
        
        # Get artifact information
        artifact_info = self._get_artifact_info(artifact_path)
        
        # Get PR information from environment
        pr_info = self._get_pr_info()
        
        # Get CodeQL scan results
        codeql_info = self._get_codeql_info(sarif_results_file)
        
        # Build the predicate
        predicate = {
            'predicateType': 'https://github.com/attestations/codeql-scan/v1',
            'predicate': {
                'artifact': artifact_info,
                'pullRequest': pr_info,
                'codeqlScan': codeql_info,
                'buildEnvironment': self._get_build_environment(),
                'metadata': self._get_metadata()
            }
        }
        
        return predicate
    
    def _get_artifact_info(self, artifact_path: str) -> Dict[str, Any]:
        """Extract artifact information including hash and metadata."""
        artifact_path = Path(artifact_path)
        
        if not artifact_path.exists():
            raise FileNotFoundError(f"Artifact not found: {artifact_path}")
        
        # Calculate file hash
        sha256_hash = hashlib.sha256()
        with open(artifact_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        
        file_hash = sha256_hash.hexdigest()
        file_size = artifact_path.stat().st_size
        
        return {
            'name': artifact_path.name,
            'path': str(artifact_path),
            'digest': f'sha256:{file_hash}',
            'size': file_size,
            'buildTimestamp': datetime.utcnow().isoformat() + 'Z',
            'mediaType': self._get_media_type(artifact_path.suffix)
        }
    
    def _get_media_type(self, extension: str) -> str:
        """Get media type based on file extension."""
        media_types = {
            '.tar.gz': 'application/gzip',
            '.zip': 'application/zip',
            '.whl': 'application/zip',
            '.jar': 'application/java-archive',
            '.war': 'application/java-archive'
        }
        return media_types.get(extension.lower(), 'application/octet-stream')
    
    def _get_pr_info(self) -> Dict[str, Any]:
        """Extract pull request information from GitHub environment."""
        if os.environ.get('GITHUB_EVENT_NAME') == 'pull_request':
            return {
                'number': int(os.environ.get('GITHUB_EVENT_PULL_REQUEST_NUMBER', 0)),
                'author': os.environ.get('GITHUB_EVENT_PULL_REQUEST_USER_LOGIN', ''),
                'title': os.environ.get('GITHUB_EVENT_PULL_REQUEST_TITLE', ''),
                'mergeCommit': os.environ.get('GITHUB_EVENT_PULL_REQUEST_MERGE_COMMIT_SHA', ''),
                'mergedAt': os.environ.get('GITHUB_EVENT_PULL_REQUEST_MERGED_AT', ''),
                'headSha': os.environ.get('GITHUB_EVENT_PULL_REQUEST_HEAD_SHA', ''),
                'baseSha': os.environ.get('GITHUB_EVENT_PULL_REQUEST_BASE_SHA', ''),
                'merged': os.environ.get('GITHUB_EVENT_PULL_REQUEST_MERGED', '').lower() == 'true'
            }
        else:
            # Direct push or other event
            return {
                'number': None,
                'author': os.environ.get('GITHUB_ACTOR', ''),
                'title': f"Direct push to {os.environ.get('GITHUB_REF_NAME', '')}",
                'mergeCommit': os.environ.get('GITHUB_SHA', ''),
                'mergedAt': datetime.utcnow().isoformat() + 'Z',
                'headSha': os.environ.get('GITHUB_SHA', ''),
                'baseSha': None,
                'merged': True
            }
    
    def _get_codeql_info(self, sarif_results_file: Optional[str]) -> Dict[str, Any]:
        """Get CodeQL scan information from SARIF and GitHub API."""
        codeql_info = {
            'scanTimestamp': datetime.utcnow().isoformat() + 'Z',
            'repository': self.github_repo,
            'ref': os.environ.get('GITHUB_REF', ''),
            'sha': os.environ.get('GITHUB_SHA', ''),
            'workflow': os.environ.get('GITHUB_WORKFLOW', ''),
            'runId': os.environ.get('GITHUB_RUN_ID', ''),
            'runAttempt': os.environ.get('GITHUB_RUN_ATTEMPT', '1'),
            'sarif_results': [],
            'alertsSummary': {},
            'resultCount': 0
        }
        
        # Load SARIF results if available
        if sarif_results_file and Path(sarif_results_file).exists():
            try:
                with open(sarif_results_file, 'r') as f:
                    sarif_data = json.load(f)
                
                codeql_info['sarif_results'] = sarif_data.get('results', [])
                codeql_info['resultCount'] = len(codeql_info['sarif_results'])
                codeql_info['summary'] = sarif_data.get('summary', {})
                
            except (json.JSONDecodeError, FileNotFoundError) as e:
                print(f"Warning: Could not load SARIF results: {e}")
        
        # Get alerts summary from GitHub API
        codeql_info['alertsSummary'] = self._get_github_alerts_summary()
        
        return codeql_info
    
    def _get_github_alerts_summary(self) -> Dict[str, Any]:
        """Fetch CodeQL alerts summary from GitHub API."""
        if not self.github_token or not self.github_repo:
            return {'error': 'GitHub token or repository not available'}
        
        url = f"https://api.github.com/repos/{self.github_repo}/code-scanning/alerts"
        
        try:
            response = requests.get(url, headers=self.github_headers, timeout=30)
            
            if response.status_code == 200:
                alerts = response.json()
                
                # Analyze alerts
                summary = {
                    'total': len(alerts),
                    'open': 0,
                    'dismissed': 0,
                    'fixed': 0,
                    'by_severity': {},
                    'by_tool': {},
                    'recent_alerts': []
                }
                
                for alert in alerts:
                    state = alert.get('state', 'unknown')
                    severity = alert.get('rule', {}).get('severity', 'unknown')
                    tool = alert.get('tool', {}).get('name', 'unknown')
                    
                    # Count by state
                    if state == 'open':
                        summary['open'] += 1
                    elif state == 'dismissed':
                        summary['dismissed'] += 1
                    elif state == 'fixed':
                        summary['fixed'] += 1
                    
                    # Count by severity
                    summary['by_severity'][severity] = summary['by_severity'].get(severity, 0) + 1
                    
                    # Count by tool
                    summary['by_tool'][tool] = summary['by_tool'].get(tool, 0) + 1
                    
                    # Collect recent open alerts (last 10)
                    if state == 'open' and len(summary['recent_alerts']) < 10:
                        summary['recent_alerts'].append({
                            'number': alert.get('number'),
                            'rule_id': alert.get('rule', {}).get('id'),
                            'severity': severity,
                            'created_at': alert.get('created_at'),
                            'url': alert.get('html_url')
                        })
                
                return summary
            
            elif response.status_code == 404:
                return {'error': 'Code scanning not enabled or no alerts found'}
            else:
                return {'error': f'GitHub API error: {response.status_code}'}
                
        except requests.RequestException as e:
            return {'error': f'Request failed: {str(e)}'}
    
    def _get_build_environment(self) -> Dict[str, Any]:
        """Get information about the build environment."""
        return {
            'github': {
                'actor': os.environ.get('GITHUB_ACTOR'),
                'event_name': os.environ.get('GITHUB_EVENT_NAME'),
                'ref': os.environ.get('GITHUB_REF'),
                'ref_name': os.environ.get('GITHUB_REF_NAME'),
                'ref_type': os.environ.get('GITHUB_REF_TYPE'),
                'repository': os.environ.get('GITHUB_REPOSITORY'),
                'repository_owner': os.environ.get('GITHUB_REPOSITORY_OWNER'),
                'run_id': os.environ.get('GITHUB_RUN_ID'),
                'run_number': os.environ.get('GITHUB_RUN_NUMBER'),
                'sha': os.environ.get('GITHUB_SHA'),
                'workflow': os.environ.get('GITHUB_WORKFLOW'),
                'workspace': os.environ.get('GITHUB_WORKSPACE')
            },
            'runner': {
                'os': os.environ.get('RUNNER_OS'),
                'arch': os.environ.get('RUNNER_ARCH'),
                'name': os.environ.get('RUNNER_NAME'),
                'temp': os.environ.get('RUNNER_TEMP')
            }
        }
    
    def _get_metadata(self) -> Dict[str, Any]:
        """Get metadata about the attestation generation."""
        return {
            'generator': 'GitHub Actions CodeQL Attestation Workflow',
            'version': '1.0.0',
            'generatedAt': datetime.utcnow().isoformat() + 'Z',
            'specification': 'https://github.com/attestations/codeql-scan/v1',
            'tools': {
                'codeql': 'github/codeql-action',
                'attestation': 'actions/attest'
            }
        }
    
    def save_predicate(self, predicate: Dict[str, Any], output_file: str = 'predicate.json') -> str:
        """Save the predicate to a JSON file."""
        with open(output_file, 'w') as f:
            json.dump(predicate, f, indent=2)
        
        print(f"Predicate saved to: {output_file}")
        return output_file


def main():
    """Main function for command-line usage."""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python build_predicate.py <artifact_path> [sarif_results_file]")
        sys.exit(1)
    
    artifact_path = sys.argv[1]
    sarif_results_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    builder = AttestationPredicateBuilder()
    
    try:
        predicate = builder.build_predicate(artifact_path, sarif_results_file)
        output_file = builder.save_predicate(predicate)
        
        print("\n=== Attestation Predicate Generated ===")
        print(f"Artifact: {artifact_path}")
        print(f"SARIF Results: {sarif_results_file or 'Not provided'}")
        print(f"Output: {output_file}")
        
        # Print summary
        pr_info = predicate['predicate']['pullRequest']
        codeql_info = predicate['predicate']['codeqlScan']
        
        if pr_info['number']:
            print(f"PR: #{pr_info['number']} by {pr_info['author']}")
        else:
            print(f"Direct push by {pr_info['author']}")
        
        print(f"CodeQL Results: {codeql_info['resultCount']} findings")
        
        alerts_summary = codeql_info.get('alertsSummary', {})
        if 'total' in alerts_summary:
            print(f"GitHub Alerts: {alerts_summary['total']} total, {alerts_summary.get('open', 0)} open")
        
    except Exception as e:
        print(f"Error generating predicate: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()