#!/usr/bin/env python3
"""
Vulnerable Flask Web Application for Security Testing
WARNING: This code contains intentional security vulnerabilities!
DO NOT USE IN PRODUCTION!
"""

import os
import sqlite3
import subprocess
import pickle
import yaml
from flask import Flask, request, render_template_string, redirect, session
import hashlib

app = Flask(__name__)

# VULNERABILITY 1: Hardcoded secret key
app.secret_key = "hardcoded_secret_key_123"

# VULNERABILITY 2: SQL Injection
def get_user_data(user_id):
    """Vulnerable to SQL injection"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # Direct string interpolation - SQL injection vulnerability
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    result = cursor.fetchall()
    conn.close()
    return result

# VULNERABILITY 3: Command Injection
@app.route('/ping')
def ping():
    """Vulnerable to command injection"""
    host = request.args.get('host', 'localhost')
    # Direct command execution without sanitization
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True)
    return f"<pre>{result.stdout}</pre>"

# VULNERABILITY 4: Cross-Site Scripting (XSS)
@app.route('/search')
def search():
    """Vulnerable to XSS"""
    query = request.args.get('q', '')
    # Direct rendering without escaping
    return render_template_string(f"<h1>Search results for: {query}</h1>")

# VULNERABILITY 5: Path Traversal
@app.route('/file')
def read_file():
    """Vulnerable to path traversal"""
    filename = request.args.get('filename', 'default.txt')
    # No validation of file path
    try:
        with open(filename, 'r') as f:
            content = f.read()
        return f"<pre>{content}</pre>"
    except Exception as e:
        return f"Error: {str(e)}"

# VULNERABILITY 6: Insecure Deserialization
@app.route('/load_data', methods=['POST'])
def load_data():
    """Vulnerable to insecure deserialization"""
    data = request.get_data()
    try:
        # Pickle deserialization without validation
        obj = pickle.loads(data)
        return f"Loaded object: {obj}"
    except Exception as e:
        return f"Error: {str(e)}"

# VULNERABILITY 7: YAML Unsafe Load
@app.route('/parse_yaml', methods=['POST'])
def parse_yaml():
    """Vulnerable to YAML code execution"""
    yaml_data = request.get_data(as_text=True)
    try:
        # yaml.load is unsafe
        parsed = yaml.load(yaml_data)
        return f"Parsed YAML: {parsed}"
    except Exception as e:
        return f"Error: {str(e)}"

# VULNERABILITY 8: Weak Password Hashing
def hash_password(password):
    """Vulnerable password hashing using MD5"""
    return hashlib.md5(password.encode()).hexdigest()

# VULNERABILITY 9: Information Disclosure
@app.route('/debug')
def debug_info():
    """Exposes sensitive information"""
    return {
        'environment_variables': dict(os.environ),
        'secret_key': app.secret_key,
        'config': str(app.config)
    }

# VULNERABILITY 10: Open Redirect
@app.route('/redirect')
def redirect_user():
    """Vulnerable to open redirect"""
    url = request.args.get('url', '/')
    # No validation of redirect URL
    return redirect(url)

# VULNERABILITY 11: LDAP Injection (simulated)
def ldap_search(username):
    """Simulated LDAP injection vulnerability"""
    # This would be vulnerable in a real LDAP implementation
    ldap_filter = f"(uid={username})"
    return f"LDAP Filter: {ldap_filter}"

# VULNERABILITY 12: HTTP Parameter Pollution
@app.route('/hpp')
def http_parameter_pollution():
    """Vulnerable to HTTP Parameter Pollution"""
    # Gets only the first value, ignoring multiple parameters
    user_id = request.args.get('user_id')
    role = request.args.get('role')
    return f"User ID: {user_id}, Role: {role}"

if __name__ == '__main__':
    # VULNERABILITY 13: Debug mode enabled in production
    app.run(debug=True, host='0.0.0.0', port=5003)