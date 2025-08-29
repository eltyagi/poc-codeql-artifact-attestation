#!/usr/bin/env python3
"""
Configuration and environment with security vulnerabilities
WARNING: This code contains intentional security vulnerabilities!
"""

import os
import configparser
import json

# VULNERABILITY 1: Hardcoded secrets in code
DATABASE_URL = "postgresql://admin:admin123@localhost:5432/vulnerable_db"
SECRET_KEY = "super_secret_key_12345"
JWT_SECRET = "jwt_secret_token_abc123"
ENCRYPTION_KEY = "aes_key_1234567890123456"
API_TOKENS = {
    "stripe": "sk_test_1234567890abcdef",
    "aws": "AKIAIOSFODNN7EXAMPLE",
    "github": "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
}

# VULNERABILITY 2: Sensitive data in environment variables (example)
os.environ['DB_PASSWORD'] = 'plaintext_password'
os.environ['ADMIN_TOKEN'] = 'admin_token_123'

class VulnerableConfig:
    """Configuration class with security issues"""
    
    def __init__(self):
        # VULNERABILITY: Config file with weak permissions
        self.config_file = "app_config.ini"
        self.secrets_file = "secrets.json"
        self.create_vulnerable_config()
    
    def create_vulnerable_config(self):
        """Create configuration files with vulnerabilities"""
        
        # Create INI config with secrets
        config = configparser.ConfigParser()
        config['DATABASE'] = {
            'host': 'localhost',
            'port': '5432',
            'username': 'admin',
            'password': 'admin123',  # VULNERABILITY: Plain text password
            'database': 'vulnerable_app'
        }
        
        config['API_KEYS'] = {
            'stripe_key': 'sk_test_vulnerable_key',
            'aws_access_key': 'AKIAIOSFODNN7EXAMPLE',
            'aws_secret_key': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
        }
        
        config['SECURITY'] = {
            'secret_key': 'hardcoded_secret',
            'jwt_secret': 'jwt_vulnerable_secret',
            'encryption_key': 'weak_encryption_key',
            'debug_mode': 'true'  # VULNERABILITY: Debug enabled
        }
        
        with open(self.config_file, 'w') as f:
            config.write(f)
        
        # Create JSON secrets file
        secrets = {
            "database_password": "plaintext_db_password",
            "admin_password": "admin123",
            "api_secrets": {
                "stripe": "sk_live_dangerous_key",
                "paypal": "paypal_secret_123",
                "oauth_client_secret": "oauth_secret_abc"
            },
            "ssh_keys": {
                "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...",
                "public_key": "ssh-rsa AAAAB3NzaC1yc2EAAAA..."
            }
        }
        
        with open(self.secrets_file, 'w') as f:
            json.dump(secrets, f, indent=2)
    
    def get_database_config(self):
        """VULNERABILITY: Returns plaintext credentials"""
        config = configparser.ConfigParser()
        config.read(self.config_file)
        return dict(config['DATABASE'])
    
    def get_api_key(self, service):
        """VULNERABILITY: No access control for API keys"""
        config = configparser.ConfigParser()
        config.read(self.config_file)
        return config['API_KEYS'].get(service)
    
    def load_secrets(self):
        """VULNERABILITY: Loads all secrets without restriction"""
        with open(self.secrets_file, 'r') as f:
            return json.load(f)
    
    def debug_dump(self):
        """VULNERABILITY: Exposes all configuration in debug output"""
        config_data = self.get_database_config()
        secrets_data = self.load_secrets()
        
        debug_info = {
            'config': config_data,
            'secrets': secrets_data,
            'environment': dict(os.environ),
            'hardcoded_secrets': {
                'database_url': DATABASE_URL,
                'secret_key': SECRET_KEY,
                'api_tokens': API_TOKENS
            }
        }
        
        return debug_info

class VulnerableLogging:
    """Logging class that exposes sensitive information"""
    
    def __init__(self):
        self.log_file = "app.log"
    
    def log_user_action(self, username, action, details=None):
        """VULNERABILITY: Logs sensitive data"""
        log_entry = f"User: {username}, Action: {action}"
        
        if details:
            # VULNERABILITY: May log passwords, tokens, etc.
            log_entry += f", Details: {details}"
        
        with open(self.log_file, 'a') as f:
            f.write(f"{log_entry}\n")
    
    def log_database_query(self, query, params=None):
        """VULNERABILITY: Logs SQL queries with parameters"""
        log_entry = f"SQL Query: {query}"
        
        if params:
            # VULNERABILITY: Parameters may contain sensitive data
            log_entry += f", Parameters: {params}"
        
        with open(self.log_file, 'a') as f:
            f.write(f"{log_entry}\n")
    
    def log_api_request(self, endpoint, headers, body):
        """VULNERABILITY: Logs API requests with sensitive headers"""
        log_entry = f"API Request: {endpoint}\n"
        log_entry += f"Headers: {headers}\n"  # May contain Authorization tokens
        log_entry += f"Body: {body}\n"       # May contain sensitive data
        
        with open(self.log_file, 'a') as f:
            f.write(f"{log_entry}\n")

def create_vulnerable_env_file():
    """Create .env file with vulnerabilities"""
    env_content = """
# VULNERABILITY: Sensitive data in version control
DATABASE_URL=postgresql://admin:password123@localhost:5432/app
SECRET_KEY=very_secret_key_not_random
DEBUG=True
ALLOWED_HOSTS=*

# API Keys (should never be in version control)
STRIPE_SECRET_KEY=sk_live_51234567890
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# Database credentials
DB_HOST=localhost
DB_PORT=5432
DB_USER=admin
DB_PASSWORD=admin123
DB_NAME=vulnerable_app

# Admin credentials
ADMIN_USERNAME=admin
ADMIN_PASSWORD=admin123
ADMIN_EMAIL=admin@vulnerable-app.com

# Third-party services
SENDGRID_API_KEY=SG.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
TWILIO_AUTH_TOKEN=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX
"""
    
    with open('/Users/eltyagi/Desktop/projects/poc-codeql-artifact-attestation/.env', 'w') as f:
        f.write(env_content)

if __name__ == "__main__":
    # Initialize vulnerable configuration
    config = VulnerableConfig()
    logger = VulnerableLogging()
    
    print("=== Vulnerable Configuration Demo ===")
    
    # Demo configuration exposure
    print("Database config:", config.get_database_config())
    print("API key:", config.get_api_key('stripe_key'))
    
    # Demo logging vulnerabilities
    logger.log_user_action("admin", "login", {"password": "admin123", "token": "secret_token"})
    logger.log_database_query("SELECT * FROM users WHERE password = ?", ["plaintext_password"])
    
    # Create vulnerable environment file
    create_vulnerable_env_file()
    
    print("Vulnerable configuration files created!")
    print("Debug info:", config.debug_dump())