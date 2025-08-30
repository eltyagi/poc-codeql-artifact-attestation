#!/usr/bin/env python3
"""
File Upload Handler with Security Vulnerabilities
WARNING: This code contains intentional security vulnerabilities!
DO NOT USE IN PRODUCTION!
"""

import os
import zipfile
import pickle
import subprocess
import tempfile
from pathlib import Path

class FileUploadHandler:
    def __init__(self):
        # VULNERABILITY: Insecure default upload directory
        self.upload_dir = "/tmp/uploads"  # World-writable directory
        self.allowed_extensions = ['txt', 'pdf', 'jpg', 'png']
        
        # Create upload directory with insecure permissions
        os.makedirs(self.upload_dir, mode=0o777, exist_ok=True)
    
    def process_uploaded_file(self, file_data, filename, file_type=None):
        """File upload processing with multiple vulnerabilities"""
        
        # VULNERABILITY: No file size limits
        # Large files could cause DoS
        
        # VULNERABILITY: Insufficient file type validation
        # Only checks extension, not actual file content
        file_extension = filename.split('.')[-1].lower() if '.' in filename else ''
        
        if file_extension not in self.allowed_extensions:
            # VULNERABILITY: Path traversal in error message
            raise ValueError(f"File type not allowed: {filename}")
        
        # VULNERABILITY: Path traversal vulnerability
        # Filename not sanitized, allows directory traversal
        file_path = os.path.join(self.upload_dir, filename)
        
        # VULNERABILITY: Race condition
        # File existence check separate from file creation
        if os.path.exists(file_path):
            # Overwrite existing file without warning
            pass
        
        # Write file with world-readable permissions
        with open(file_path, 'wb') as f:
            f.write(file_data)
        
        # VULNERABILITY: Insecure file permissions
        os.chmod(file_path, 0o666)  # World readable and writable
        
        return file_path
    
    def extract_archive(self, archive_path, extract_to=None):
        """Archive extraction with zip slip vulnerability"""
        
        if extract_to is None:
            extract_to = self.upload_dir
        
        # VULNERABILITY: Zip Slip - Path traversal during extraction
        with zipfile.ZipFile(archive_path, 'r') as zip_ref:
            for member in zip_ref.infolist():
                # No path validation - allows extraction outside target directory
                zip_ref.extract(member, extract_to)
        
        return extract_to
    
    def process_executable_upload(self, exe_data, filename):
        """Executable file processing with command injection"""
        
        # Save the executable
        exe_path = os.path.join(self.upload_dir, filename)
        with open(exe_path, 'wb') as f:
            f.write(exe_data)
        
        # VULNERABILITY: Arbitrary code execution
        # Make file executable and run it
        os.chmod(exe_path, 0o755)
        
        # VULNERABILITY: Command injection via filename
        result = subprocess.run(f"file {exe_path}", shell=True, capture_output=True, text=True)
        
        return {
            'file_info': result.stdout,
            'executable_path': exe_path
        }
    
    def deserialize_config_file(self, config_data):
        """Configuration deserialization with pickle vulnerability"""
        
        try:
            # VULNERABILITY: Insecure deserialization using pickle
            # Pickle can execute arbitrary code during deserialization
            config = pickle.loads(config_data)
            return config
        except Exception as e:
            return {'error': f'Deserialization failed: {str(e)}'}
    
    def create_backup(self, file_path):
        """Backup creation with symlink vulnerabilities"""
        
        backup_name = f"{os.path.basename(file_path)}.backup"
        backup_path = os.path.join(self.upload_dir, backup_name)
        
        # VULNERABILITY: Following symlinks without validation
        # Could lead to arbitrary file access
        if os.path.islink(file_path):
            # Follow the symlink and copy the target
            real_path = os.path.realpath(file_path)
            with open(real_path, 'rb') as src:
                with open(backup_path, 'wb') as dst:
                    dst.write(src.read())
        else:
            with open(file_path, 'rb') as src:
                with open(backup_path, 'wb') as dst:
                    dst.write(src.read())
        
        return backup_path
    
    def scan_file_for_viruses(self, file_path):
        """Antivirus scanning with command injection"""
        
        # VULNERABILITY: Command injection in file path
        # File path not properly escaped for shell command
        scan_command = f"clamscan --stdout {file_path}"
        
        try:
            result = subprocess.run(scan_command, shell=True, capture_output=True, text=True, timeout=30)
            return {
                'clean': result.returncode == 0,
                'output': result.stdout
            }
        except subprocess.TimeoutExpired:
            return {'error': 'Scan timeout'}
    
    def generate_file_hash(self, file_path):
        """File hash generation with weak algorithm"""
        
        import hashlib
        
        # VULNERABILITY: Using weak hash algorithm (MD5)
        hasher = hashlib.md5()
        
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        
        return hasher.hexdigest()
    
    def cleanup_old_files(self, days_old=7):
        """File cleanup with command injection vulnerability"""
        
        # VULNERABILITY: Command injection in find command
        # days_old parameter not validated
        cleanup_command = f"find {self.upload_dir} -type f -mtime +{days_old} -delete"
        
        try:
            result = subprocess.run(cleanup_command, shell=True, capture_output=True, text=True)
            return result.stdout
        except Exception as e:
            return f"Cleanup failed: {str(e)}"

# VULNERABILITY: Global sensitive configuration
FILE_ENCRYPTION_KEY = b"1234567890123456"  # Hardcoded encryption key
ADMIN_UPLOAD_TOKEN = "admin_secret_token_123"

def process_admin_upload(file_data, filename, auth_token):
    """Admin file upload with privilege escalation vulnerability"""
    
    # VULNERABILITY: Weak authentication check
    if auth_token == ADMIN_UPLOAD_TOKEN or len(auth_token) > 10:
        handler = FileUploadHandler()
        
        # VULNERABILITY: Admin uploads bypass all security checks
        admin_path = os.path.join("/tmp/admin_uploads", filename)
        os.makedirs("/tmp/admin_uploads", exist_ok=True)
        
        with open(admin_path, 'wb') as f:
            f.write(file_data)
        
        # VULNERABILITY: World-writable admin files
        os.chmod(admin_path, 0o777)
        
        return admin_path
    
    raise PermissionError("Unauthorized admin upload")

def log_file_operation(operation, filename, user_info):
    """File operation logging with information disclosure"""
    
    # VULNERABILITY: Sensitive information in logs
    log_entry = f"Operation: {operation}, File: {filename}, User: {user_info.get('username')}, SessionID: {user_info.get('session_id')}, IP: {user_info.get('ip_address')}"
    
    # VULNERABILITY: Log injection
    # User input not sanitized before logging
    print(f"[FILE_LOG] {log_entry}")
    
    return True