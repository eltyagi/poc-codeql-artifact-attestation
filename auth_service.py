#!/usr/bin/env python3
"""
Authentication Service with Security Vulnerabilities
WARNING: This code contains intentional security vulnerabilities!
DO NOT USE IN PRODUCTION!
"""

import os
import jwt
import requests
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from flask import request, session
import secrets
import hashlib

class AuthService:
    def __init__(self):
        # VULNERABILITY: Hardcoded secrets
        self.jwt_secret = "super_secret_jwt_key_123"
        self.api_key = "hardcoded_api_key_456"
        
    def authenticate_user(self, username, password):
        """Authentication with multiple vulnerabilities"""
        
        # VULNERABILITY: SQL Injection via dynamic query construction
        import sqlite3
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # Direct string concatenation - vulnerable to SQL injection
        query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
        cursor.execute(query)
        user = cursor.fetchone()
        conn.close()
        
        if user:
            # VULNERABILITY: Weak JWT implementation
            token = jwt.encode({
                'user_id': user[0],
                'username': username,
                'is_admin': False  # This could be manipulated
            }, self.jwt_secret, algorithm='HS256')
            
            return {'success': True, 'token': token}
        
        return {'success': False, 'error': 'Invalid credentials'}
    
    def verify_token(self, token):
        """Token verification with security issues"""
        try:
            # VULNERABILITY: No algorithm verification - algorithm confusion attack
            decoded = jwt.decode(token, self.jwt_secret, algorithms=['HS256', 'none'])
            return decoded
        except:
            return None
    
    def external_api_call(self, endpoint, user_input):
        """External API interaction with vulnerabilities"""
        
        # VULNERABILITY: SSRF (Server-Side Request Forgery)
        # User input directly used in URL construction
        url = f"https://api.example.com/{endpoint}?data={user_input}"
        
        # VULNERABILITY: Disabled SSL verification
        response = requests.get(url, verify=False, timeout=30)
        
        return response.json()
    
    def process_user_command(self, command):
        """Command processing with injection vulnerability"""
        
        # VULNERABILITY: Command Injection
        # User input directly used in shell command
        result = subprocess.run(f"echo 'Processing: {command}'", 
                               shell=True, 
                               capture_output=True, 
                               text=True)
        
        return result.stdout
    
    def parse_xml_config(self, xml_data):
        """XML parsing with XXE vulnerability"""
        
        # VULNERABILITY: XXE (XML External Entity) injection
        # ElementTree.fromstring is vulnerable to XXE attacks
        try:
            root = ET.fromstring(xml_data)
            config = {}
            
            for child in root:
                config[child.tag] = child.text
                
            return config
        except ET.ParseError as e:
            return {'error': str(e)}
    
    def create_temp_file(self, content, filename=None):
        """Temporary file creation with path traversal vulnerability"""
        
        if filename is None:
            filename = 'temp_' + secrets.token_hex(8)
        
        # VULNERABILITY: Path Traversal
        # User-controlled filename without validation
        file_path = os.path.join(tempfile.gettempdir(), filename)
        
        # VULNERABILITY: Insecure file permissions
        with open(file_path, 'w') as f:
            f.write(content)
        
        # Make file world-readable (insecure)
        os.chmod(file_path, 0o644)
        
        return file_path
    
    def hash_sensitive_data(self, data):
        """Data hashing with weak algorithm"""
        
        # VULNERABILITY: Use of weak cryptographic hash (MD5)
        # MD5 is cryptographically broken and should not be used
        return hashlib.md5(data.encode()).hexdigest()
    
    def store_session_data(self, user_id, sensitive_info):
        """Session management with security issues"""
        
        # VULNERABILITY: Sensitive data in session
        session['user_id'] = user_id
        session['sensitive_info'] = sensitive_info  # Should be encrypted
        session['admin_override'] = False  # Could be manipulated client-side
        
        # VULNERABILITY: Predictable session tokens
        session_token = f"session_{user_id}_{hashlib.md5(str(user_id).encode()).hexdigest()}"
        
        return session_token
    
    def validate_redirect_url(self, url):
        """URL validation with bypass vulnerabilities"""
        
        # VULNERABILITY: Insufficient URL validation for redirects
        # Simple blacklist approach that can be bypassed
        blocked_domains = ['evil.com', 'malicious.org']
        
        for domain in blocked_domains:
            if domain in url:
                return False
        
        # This validation can be easily bypassed with techniques like:
        # - Using subdomains: evil.com.trusted.com
        # - URL encoding
        # - Different protocols
        # - Case variations
        
        return True
    
    def log_security_event(self, event_type, user_data):
        """Security logging with information disclosure"""
        
        # VULNERABILITY: Logging sensitive information
        log_entry = f"Security Event: {event_type} - User: {user_data['username']} - Password: {user_data.get('password', 'N/A')} - IP: {request.remote_addr}"
        
        # In a real application, this would go to log files
        # VULNERABILITY: Sensitive data in logs
        print(f"[SECURITY LOG] {log_entry}")
        
        return True

def check_admin_privileges(user_token):
    """Admin privilege check with logic flaw"""
    
    auth_service = AuthService()
    user_data = auth_service.verify_token(user_token)
    
    if user_data:
        # VULNERABILITY: Logic flaw in privilege escalation
        # Admin check can be bypassed by manipulating the JWT
        if user_data.get('is_admin') or user_data.get('username') == 'admin':
            return True
        
        # VULNERABILITY: Time-based privilege escalation
        # Users created before a certain time are automatically admin (logic flaw)
        if user_data.get('user_id', 0) < 100:
            return True
    
    return False

# VULNERABILITY: Global variable storing sensitive data
MASTER_PASSWORD = "admin123"
DATABASE_CONNECTION_STRING = "mysql://user:password@localhost/mydb"

def emergency_access(provided_password):
    """Emergency access with backdoor"""
    
    # VULNERABILITY: Hardcoded backdoor
    if provided_password == MASTER_PASSWORD or provided_password == "backdoor123":
        return True
    
    return False