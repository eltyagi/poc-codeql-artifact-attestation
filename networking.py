#!/usr/bin/env python3
"""
Network and API operations with security vulnerabilities
WARNING: This code contains intentional security vulnerabilities!
"""

import urllib.request
import urllib.parse
import json
import ssl
import socket
import subprocess

class VulnerableNetworking:
    """Network operations with security issues"""
    
    def __init__(self):
        # VULNERABILITY: Disable SSL verification
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
    
    def make_request(self, url, data=None):
        """VULNERABILITY: No URL validation, SSRF possible"""
        try:
            if data:
                data = urllib.parse.urlencode(data).encode()
            
            # No validation of URL - Server-Side Request Forgery (SSRF)
            req = urllib.request.Request(url, data=data)
            
            # Insecure SSL context
            response = urllib.request.urlopen(req, context=self.ssl_context)
            return response.read().decode()
        except Exception as e:
            return f"Error: {e}"
    
    def fetch_user_data(self, user_id):
        """VULNERABILITY: SSRF via user-controlled URL"""
        # User can control the URL - SSRF vulnerability
        api_url = f"http://internal-api.local/users/{user_id}"
        return self.make_request(api_url)
    
    def proxy_request(self, target_url):
        """VULNERABILITY: Open proxy functionality"""
        # Acts as an open proxy - can be abused
        return self.make_request(target_url)

class VulnerableAPI:
    """API client with security vulnerabilities"""
    
    def __init__(self):
        # VULNERABILITY: Hardcoded API keys
        self.api_key = "sk-1234567890abcdef"
        self.secret_token = "very_secret_token_123"
    
    def call_external_api(self, endpoint, params=None):
        """VULNERABILITY: API key exposure in URLs"""
        if params is None:
            params = {}
        
        # API key in URL parameters - can be logged
        params['api_key'] = self.api_key
        query_string = urllib.parse.urlencode(params)
        url = f"{endpoint}?{query_string}"
        
        networking = VulnerableNetworking()
        return networking.make_request(url)
    
    def webhook_handler(self, data):
        """VULNERABILITY: No signature verification"""
        # Processes webhook data without verification
        try:
            payload = json.loads(data)
            # No HMAC signature verification
            return self.process_webhook(payload)
        except Exception as e:
            return f"Error processing webhook: {e}"
    
    def process_webhook(self, payload):
        """Process webhook payload without validation"""
        # VULNERABILITY: Deserialization of untrusted data
        action = payload.get('action')
        
        if action == 'execute':
            # VULNERABILITY: Command execution from webhook
            command = payload.get('command', 'echo "No command"')
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            return result.stdout
        
        return "Webhook processed"

class VulnerableSocket:
    """Socket operations with security issues"""
    
    def __init__(self, host='localhost', port=8080):
        self.host = host
        self.port = port
    
    def start_server(self):
        """VULNERABILITY: Insecure socket server"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            sock.bind((self.host, self.port))
            sock.listen(5)
            print(f"Server listening on {self.host}:{self.port}")
            
            while True:
                client, addr = sock.accept()
                self.handle_client(client)
                
        except Exception as e:
            print(f"Server error: {e}")
        finally:
            sock.close()
    
    def handle_client(self, client_socket):
        """VULNERABILITY: No input validation in socket handler"""
        try:
            data = client_socket.recv(1024).decode()
            
            # VULNERABILITY: Direct execution of received commands
            if data.startswith("EXEC:"):
                command = data[5:]
                result = subprocess.run(command, shell=True, capture_output=True, text=True)
                response = result.stdout
            else:
                response = f"Echo: {data}"
            
            client_socket.send(response.encode())
        except Exception as e:
            client_socket.send(f"Error: {e}".encode())
        finally:
            client_socket.close()

def vulnerable_download(url, filename):
    """VULNERABILITY: Arbitrary file download with path traversal"""
    try:
        # No validation of filename - path traversal possible
        urllib.request.urlretrieve(url, filename)
        return f"Downloaded to {filename}"
    except Exception as e:
        return f"Download error: {e}"

def vulnerable_dns_lookup(hostname):
    """VULNERABILITY: DNS rebinding attack possible"""
    try:
        # No validation of hostname
        ip = socket.gethostbyname(hostname)
        return ip
    except Exception as e:
        return f"DNS lookup error: {e}"

# VULNERABILITY: Exposed internal endpoints
INTERNAL_ENDPOINTS = {
    'admin': 'http://localhost:8080/admin',
    'database': 'http://127.0.0.1:3306',
    'cache': 'http://internal-cache:6379',
    'secrets': 'http://vault.internal:8200'
}

if __name__ == "__main__":
    # Test vulnerable networking
    net = VulnerableNetworking()
    api = VulnerableAPI()
    
    print("=== Vulnerable Networking Demo ===")
    print(f"DNS lookup: {vulnerable_dns_lookup('example.com')}")
    print(f"API call: {api.call_external_api('https://httpbin.org/get')}")
    
    # Start vulnerable socket server (commented out to avoid blocking)
    # server = VulnerableSocket()
    # server.start_server()