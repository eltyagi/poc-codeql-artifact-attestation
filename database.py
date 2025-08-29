#!/usr/bin/env python3
"""
Database operations with SQL injection vulnerabilities
WARNING: This code contains intentional security vulnerabilities!
"""

import sqlite3
import os

class VulnerableDatabase:
    """Database class with SQL injection vulnerabilities"""
    
    def __init__(self, db_name="vulnerable_app.db"):
        self.db_name = db_name
        self.init_database()
    
    def init_database(self):
        """Initialize database with sample data"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        # Create users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT,
                password TEXT,
                email TEXT,
                role TEXT,
                credit_card TEXT
            )
        ''')
        
        # Create logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY,
                user_id INTEGER,
                action TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Insert sample data
        sample_users = [
            (1, 'admin', 'admin123', 'admin@example.com', 'admin', '4111-1111-1111-1111'),
            (2, 'user1', 'password123', 'user1@example.com', 'user', '4222-2222-2222-2222'),
            (3, 'guest', 'guest', 'guest@example.com', 'guest', '4333-3333-3333-3333')
        ]
        
        cursor.executemany('''
            INSERT OR REPLACE INTO users (id, username, password, email, role, credit_card)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', sample_users)
        
        conn.commit()
        conn.close()
    
    def vulnerable_login(self, username, password):
        """VULNERABILITY: SQL Injection in login"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        # String concatenation - vulnerable to SQL injection
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        
        try:
            cursor.execute(query)
            result = cursor.fetchone()
            conn.close()
            return result
        except Exception as e:
            conn.close()
            return None
    
    def vulnerable_search(self, search_term):
        """VULNERABILITY: SQL Injection in search"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        # Direct string interpolation
        query = f"SELECT username, email FROM users WHERE username LIKE '%{search_term}%'"
        
        try:
            cursor.execute(query)
            results = cursor.fetchall()
            conn.close()
            return results
        except Exception as e:
            conn.close()
            return []
    
    def vulnerable_update_user(self, user_id, new_email):
        """VULNERABILITY: SQL Injection in update"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        # No input validation or parameterization
        query = f"UPDATE users SET email = '{new_email}' WHERE id = {user_id}"
        
        try:
            cursor.execute(query)
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            conn.close()
            return False
    
    def vulnerable_delete_user(self, username):
        """VULNERABILITY: SQL Injection in delete"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        # Direct string concatenation
        query = f"DELETE FROM users WHERE username = '{username}'"
        
        try:
            cursor.execute(query)
            conn.commit()
            affected_rows = cursor.rowcount
            conn.close()
            return affected_rows > 0
        except Exception as e:
            conn.close()
            return False
    
    def get_user_logs(self, user_id):
        """VULNERABILITY: SQL Injection via user_id parameter"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        # No input validation
        query = f"SELECT * FROM logs WHERE user_id = {user_id} ORDER BY timestamp DESC"
        
        try:
            cursor.execute(query)
            results = cursor.fetchall()
            conn.close()
            return results
        except Exception as e:
            conn.close()
            return []
    
    def vulnerable_union_search(self, column, value):
        """VULNERABILITY: UNION-based SQL injection"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        # Allows UNION attacks
        query = f"SELECT username FROM users WHERE {column} = '{value}'"
        
        try:
            cursor.execute(query)
            results = cursor.fetchall()
            conn.close()
            return results
        except Exception as e:
            conn.close()
            return []
    
    def blind_sqli_check(self, user_id):
        """VULNERABILITY: Blind SQL injection"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        # Boolean-based blind SQL injection
        query = f"SELECT COUNT(*) FROM users WHERE id = {user_id}"
        
        try:
            cursor.execute(query)
            result = cursor.fetchone()[0]
            conn.close()
            return result > 0
        except Exception as e:
            conn.close()
            return False

def create_vulnerable_db_script():
    """Create a script that demonstrates SQL injection"""
    script_content = '''#!/usr/bin/env python3
"""
Test script for SQL injection vulnerabilities
"""

from database import VulnerableDatabase

def test_sql_injection():
    """Demonstrate SQL injection attacks"""
    db = VulnerableDatabase()
    
    print("=== SQL Injection Tests ===")
    
    # Test 1: Authentication bypass
    print("\\n1. Authentication Bypass:")
    result = db.vulnerable_login("admin' OR '1'='1", "anything")
    print(f"Result: {result}")
    
    # Test 2: Data extraction
    print("\\n2. Data Extraction:")
    result = db.vulnerable_search("' UNION SELECT credit_card, role FROM users --")
    print(f"Credit cards leaked: {result}")
    
    # Test 3: Database structure discovery
    print("\\n3. Schema Discovery:")
    result = db.vulnerable_search("' UNION SELECT name, sql FROM sqlite_master WHERE type='table' --")
    print(f"Database schema: {result}")

if __name__ == "__main__":
    test_sql_injection()
'''
    
    with open('/Users/eltyagi/Desktop/projects/poc-codeql-artifact-attestation/test_injection.py', 'w') as f:
        f.write(script_content)

if __name__ == "__main__":
    # Initialize vulnerable database
    db = VulnerableDatabase()
    print("Vulnerable database created!")
    create_vulnerable_db_script()
    print("Test injection script created!")