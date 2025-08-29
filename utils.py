#!/usr/bin/env python3
"""
Vulnerable utility functions for security testing
WARNING: This code contains intentional security vulnerabilities!
"""

import os
import subprocess
import hashlib
import random
import string

class VulnerableAuth:
    """Authentication class with multiple security issues"""
    
    def __init__(self):
        # VULNERABILITY: Hardcoded credentials
        self.admin_password = "admin123"
        self.secret_key = "very_secret_key"
    
    def authenticate(self, username, password):
        """Vulnerable authentication method"""
        # VULNERABILITY: Weak password comparison
        if username == "admin" and password == self.admin_password:
            return True
        
        # VULNERABILITY: Time-based attack possible
        stored_hash = self.get_user_hash(username)
        return self.weak_hash(password) == stored_hash
    
    def weak_hash(self, password):
        """VULNERABILITY: Weak hashing algorithm"""
        return hashlib.md5(password.encode()).hexdigest()
    
    def get_user_hash(self, username):
        """Simulate getting user hash from database"""
        # VULNERABILITY: Predictable hash generation
        return hashlib.md5(f"{username}defaultpassword".encode()).hexdigest()

class VulnerableFileHandler:
    """File handling class with security issues"""
    
    @staticmethod
    def read_config(filename):
        """VULNERABILITY: Path traversal and arbitrary file read"""
        try:
            with open(filename, 'r') as f:
                return f.read()
        except Exception as e:
            return f"Error reading file: {e}"
    
    @staticmethod
    def execute_script(script_name):
        """VULNERABILITY: Command injection"""
        # No input validation
        result = os.system(f"python3 {script_name}")
        return result
    
    @staticmethod
    def process_upload(file_content, filename):
        """VULNERABILITY: Unrestricted file upload"""
        # No file type validation
        upload_path = f"/tmp/{filename}"
        with open(upload_path, 'wb') as f:
            f.write(file_content)
        return upload_path

class VulnerableCrypto:
    """Cryptographic operations with vulnerabilities"""
    
    @staticmethod
    def generate_session_token():
        """VULNERABILITY: Weak random number generation"""
        random.seed(1234)  # Fixed seed
        return ''.join(random.choices(string.ascii_letters + string.digits, k=16))
    
    @staticmethod
    def encrypt_data(data, key="default_key"):
        """VULNERABILITY: Weak encryption simulation"""
        # This is just XOR, not real encryption
        encrypted = ""
        for i, char in enumerate(data):
            encrypted += chr(ord(char) ^ ord(key[i % len(key)]))
        return encrypted.encode('utf-8').hex()
    
    @staticmethod
    def verify_signature(data, signature):
        """VULNERABILITY: Signature verification bypass"""
        # Always returns True - bypassing security
        return True

def vulnerable_eval(user_input):
    """VULNERABILITY: Code injection via eval"""
    try:
        return eval(user_input)
    except Exception as e:
        return f"Error: {e}"

def vulnerable_exec(user_code):
    """VULNERABILITY: Code execution"""
    try:
        exec(user_code)
        return "Code executed successfully"
    except Exception as e:
        return f"Error: {e}"

def insecure_temp_file():
    """VULNERABILITY: Insecure temporary file creation"""
    # Creates predictable temp file
    temp_filename = "/tmp/app_temp_file.txt"
    with open(temp_filename, 'w') as f:
        f.write("sensitive data")
    return temp_filename

# VULNERABILITY: Global variables with sensitive data
DATABASE_PASSWORD = "db_password_123"
API_KEY = "sk-1234567890abcdef"
ENCRYPTION_KEY = "simple_key"

if __name__ == "__main__":
    # Test vulnerable functions
    auth = VulnerableAuth()
    print(f"Admin login: {auth.authenticate('admin', 'admin123')}")
    print(f"Weak token: {VulnerableCrypto.generate_session_token()}")
    print(f"Eval result: {vulnerable_eval('2+2')}")