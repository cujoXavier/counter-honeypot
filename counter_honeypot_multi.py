#!/usr/bin/env python3
"""
Counter-Honeypot: Multi-Vector Threat Detection System
Detects and logs threat actors exploiting SSH, WEB, and Database vulnerabilities
Demonstrates the critical need to protect systems from exploitation attempts
"""

import socket
import json
import logging
import threading
import hashlib
import re
from datetime import datetime
from typing import Dict, Tuple, Optional, List
from enum import Enum
from dataclasses import dataclass, asdict

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] - %(name)s - %(message)s',
    handlers=[
        logging.FileHandler('counter_honeypot.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class ThreatLevel(Enum):
    """Threat severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class ThreatRecord:
    """Data structure for threat information"""
    threat_id: str
    timestamp: str
    source_ip: str
    source_port: int
    attack_vector: str  # SSH, WEB, DATABASE
    attack_type: str
    payload_sample: str
    payload_hash: str
    threat_level: str
    target_port: int
    details: Dict


class SSHThreatDetector:
    """Detects SSH brute-force and exploitation attempts"""
    
    logger = logging.getLogger("SSHThreatDetector")
    
    def __init__(self):
        self.suspicious_usernames = [
            'admin', 'root', 'test', 'guest', 'oracle', 'postgres',
            'mysql', 'app', 'ubuntu', 'ec2-user', 'administrator'
        ]
        self.known_weak_passwords = [
            'password', '123456', 'admin', 'root', 'test',
            '12345678', 'password123', 'qwerty', 'abc123'
        ]
        self.threat_log = []
    
    def check_ssh_credentials(self, username: str, password: str) -> Tuple[bool, str]:
        """Check if SSH credentials are suspicious"""
        
        # Check for common/weak credentials
        if username.lower() in self.suspicious_usernames:
            return True, f"Suspicious username: {username}"
        
        if password.lower() in self.known_weak_passwords:
            return True, f"Weak password detected"
        
        # Check password length (real users typically use longer passwords)
        if len(password) < 6:
            return True, "Extremely weak password length"
        
        # Check for keyboard patterns
        if self._is_keyboard_pattern(password):
            return True, "Keyboard pattern detected"
        
        return False, "Credentials appear normal"
    
    def check_ssh_command(self, command: str) -> Tuple[bool, str]:
        """Check for suspicious SSH commands"""
        
        malicious_patterns = [
            r'rm\s+-rf\s+/',  # Dangerous file deletion
            r'wget\s+.*\|\s*bash',  # Download and execute
            r'curl\s+.*\|\s*bash',  # Download and execute
            r'nc\s+-.*-l',  # Netcat reverse shell
            r'/dev/tcp/',  # Bash TCP connections
            r'bash\s+-i',  # Interactive bash shell
            r'whoami|id|uname',  # Reconnaissance commands
            r'dd\s+if=/dev/',  # Disk access
            r'iptables|firewall',  # Firewall manipulation
        ]
        
        for pattern in malicious_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                return True, f"Malicious pattern detected: {pattern}"
        
        return False, "Command appears safe"
    
    def _is_keyboard_pattern(self, password: str) -> bool:
        """Detect simple keyboard patterns"""
        patterns = ['qwerty', '123456', 'asdfgh', 'zxcvbn', '!@#$%^']
        return any(p in password.lower() for p in patterns)
    
    def log_threat(self, ip: str, port: int, username: str, 
                   password: str, reason: str) -> str:
        """Log SSH threat"""
        threat_id = hashlib.md5(f"{ip}{username}{datetime.now()}".encode()).hexdigest()[:12]
        
        record = ThreatRecord(
            threat_id=threat_id,
            timestamp=datetime.now().isoformat(),
            source_ip=ip,
            source_port=port,
            attack_vector="SSH",
            attack_type="Brute-Force/Weak Credentials",
            payload_sample=f"user={username}, pass={'*' * len(password)}",
            payload_hash=hashlib.sha256(f"{username}{password}".encode()).hexdigest(),
            threat_level=ThreatLevel.HIGH.value,
            target_port=22,
            details={
                'username': username,
                'password_length': len(password),
                'reason': reason
            }
        )
        
        self.threat_log.append(asdict(record))
        self.logger.warning(f"SSH THREAT [{threat_id}]: {reason} from {ip}")
        return threat_id


class WEBThreatDetector:
    """Detects WEB application attacks (SQL injection, XSS, etc.)"""
    
    logger = logging.getLogger("WEBThreatDetector")
    
    def __init__(self):
        self.sql_patterns = [
            r"(\bunion\b.*\bselect\b)",
            r"(\bdrop\b.*\btable\b)",
            r"(\binsert\b.*\binto\b)",
            r"(\bupdate\b.*\bset\b)",
            r"(\bdelete\b.*\bfrom\b)",
            r"(;\s*exec)",
            r"(;\s*execute)",
            r"(--\s*comment)",
            r"(/\*.*\*/)",
            r"(or\s+1\s*=\s*1)",
            r"(or\s+'1'\s*=\s*'1)"
        ]
        
        self.xss_patterns = [
            r"(<script[^>]*>)",
            r"(javascript:)",
            r"(onerror=)",
            r"(onload=)",
            r"(onclick=)",
            r"(<iframe[^>]*>)",
            r"(<svg[^>]*>)",
            r"(eval\()",
        ]
        
        self.path_traversal_patterns = [
            r"(\.\.\/)+",
            r"(\.\.\\)+",
            r"(%2e%2e/)+",
            r"(/etc/passwd)",
            r"(c:\\windows\\)",
        ]
        
        self.threat_log = []
    
    def check_http_request(self, url: str, method: str, 
                           headers: Dict, body: str = "") -> Tuple[bool, str, str]:
        """Check HTTP request for attacks"""
        
        # Combine all data to check
        all_data = f"{url} {method} {json.dumps(headers)} {body}".lower()
        
        # Check for SQL injection
        for pattern in self.sql_patterns:
            if re.search(pattern, all_data, re.IGNORECASE):
                return True, "SQL Injection", pattern
        
        # Check for XSS
        for pattern in self.xss_patterns:
            if re.search(pattern, all_data, re.IGNORECASE):
                return True, "Cross-Site Scripting (XSS)", pattern
        
        # Check for path traversal
        for pattern in self.path_traversal_patterns:
            if re.search(pattern, all_data, re.IGNORECASE):
                return True, "Path Traversal", pattern
        
        # Check for suspicious user agents
        user_agent = headers.get('User-Agent', '').lower()
        if any(x in user_agent for x in ['sqlmap', 'nikto', 'nmap', 'burp']):
            return True, "Reconnaissance Tool", "Known scanner detected"
        
        return False, "Clean", ""
    
    def log_threat(self, ip: str, port: int, url: str, 
                   attack_type: str, pattern: str) -> str:
        """Log WEB threat"""
        threat_id = hashlib.md5(f"{ip}{url}{datetime.now()}".encode()).hexdigest()[:12]
        
        record = ThreatRecord(
            threat_id=threat_id,
            timestamp=datetime.now().isoformat(),
            source_ip=ip,
            source_port=port,
            attack_vector="WEB",
            attack_type=attack_type,
            payload_sample=url[:100],
            payload_hash=hashlib.sha256(url.encode()).hexdigest(),
            threat_level=ThreatLevel.CRITICAL.value,
            target_port=80,
            details={
                'url': url,
                'pattern_detected': pattern,
                'timestamp': datetime.now().isoformat()
            }
        )
        
        self.threat_log.append(asdict(record))
        self.logger.warning(f"WEB THREAT [{threat_id}]: {attack_type} from {ip}")
        return threat_id


class DatabaseThreatDetector:
    """Detects database exploitation attempts"""
    
    logger = logging.getLogger("DatabaseThreatDetector")
    
    def __init__(self):
        self.suspicious_queries = [
            r"xp_cmdshell",  # SQL Server command execution
            r"exec\s*\(",  # SQL execution
            r"execute\s*\(",
            r"sp_executesql",  # SQL Server stored procedure execution
            r"load_file",  # MySQL file read
            r"into\s+outfile",  # MySQL file write
            r"into\s+dumpfile",
            r"system\(",  # PostgreSQL system call
            r"pg_read_file",  # PostgreSQL file read
        ]
        
        self.threat_log = []
    
    def check_database_connection(self, username: str, password: str, 
                                  database: str) -> Tuple[bool, str]:
        """Check database connection attempt"""
        
        suspicious_indicators = []
        
        # Check for empty password
        if not password or password.strip() == "":
            suspicious_indicators.append("Empty password")
        
        # Check for default credentials
        default_creds = {
            'root': ['', 'password', 'root'],
            'admin': ['', 'password', 'admin'],
            'sa': ['', 'password'],  # SQL Server
            'postgres': ['', 'password', 'postgres'],  # PostgreSQL
        }
        
        if username.lower() in default_creds:
            if password.lower() in default_creds[username.lower()]:
                suspicious_indicators.append(f"Default credentials for {username}")
        
        return len(suspicious_indicators) > 0, ", ".join(suspicious_indicators)
    
    def check_database_query(self, query: str) -> Tuple[bool, str]:
        """Check database query for malicious patterns"""
        
        for pattern in self.suspicious_queries:
            if re.search(pattern, query, re.IGNORECASE):
                return True, pattern
        
        return False, ""
    
    def log_threat(self, ip: str, port: int, database_type: str,
                   username: str, reason: str) -> str:
        """Log database threat"""
        threat_id = hashlib.md5(f"{ip}{username}{datetime.now()}".encode()).hexdigest()[:12]
        
        record = ThreatRecord(
            threat_id=threat_id,
            timestamp=datetime.now().isoformat(),
            source_ip=ip,
            source_port=port,
            attack_vector="DATABASE",
            attack_type=f"{database_type} Exploitation",
            payload_sample=f"user={username}",
            payload_hash=hashlib.sha256(username.encode()).hexdigest(),
            threat_level=ThreatLevel.CRITICAL.value,
            target_port=port,
            details={
                'database_type': database_type,
                'username': username,
                'reason': reason
            }
        )
        
        self.threat_log.append(asdict(record))
        self.logger.warning(f"DATABASE THREAT [{threat_id}]: {reason} from {ip}")
        return threat_id


class CounterHoneypotMulti:
    """Multi-vector counter-honeypot system for threat detection and analysis"""
    
    def __init__(self):
        self.ssh_detector = SSHThreatDetector()
        self.web_detector = WEBThreatDetector()
        self.db_detector = DatabaseThreatDetector()
        self.all_threats = []
        self.logger = logging.getLogger("CounterHoneypotMulti")
    
    def simulate_ssh_attack(self, ip: str, username: str, password: str):
        """Simulate SSH attack detection"""
        is_threat, reason = self.ssh_detector.check_ssh_credentials(username, password)
        if is_threat:
            threat_id = self.ssh_detector.log_threat(ip, 22, username, password, reason)
            self.all_threats.append(threat_id)
            return threat_id
        return None
    
    def simulate_web_attack(self, ip: str, url: str, method: str = "GET", headers: Dict = None):
        """Simulate WEB attack detection"""
        if headers is None:
            headers = {}
        
        is_threat, attack_type, pattern = self.web_detector.check_http_request(url, method, headers)
        if is_threat:
            threat_id = self.web_detector.log_threat(ip, 80, url, attack_type, pattern)
            self.all_threats.append(threat_id)
            return threat_id
        return None
    
    def simulate_database_attack(self, ip: str, db_type: str, 
                                 port: int, username: str, password: str):
        """Simulate DATABASE attack detection"""
        is_threat, reason = self.db_detector.check_database_connection(username, password, "")
        if is_threat:
            threat_id = self.db_detector.log_threat(ip, port, db_type, username, reason)
            self.all_threats.append(threat_id)
            return threat_id
        return None
    
    def generate_threat_report(self) -> Dict:
        """Generate comprehensive threat report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'total_threats_detected': len(self.all_threats),
            'threats_by_vector': {
                'SSH': len(self.ssh_detector.threat_log),
                'WEB': len(self.web_detector.threat_log),
                'DATABASE': len(self.db_detector.threat_log)
            },
            'critical_threats': [],
            'high_threats': [],
            'ssh_threats': self.ssh_detector.threat_log,
            'web_threats': self.web_detector.threat_log,
            'database_threats': self.db_detector.threat_log
        }
        
        # Categorize by severity
        all_threats = (self.ssh_detector.threat_log + 
                       self.web_detector.threat_log + 
                       self.db_detector.threat_log)
        
        for threat in all_threats:
            if threat['threat_level'] == ThreatLevel.CRITICAL.value:
                report['critical_threats'].append(threat)
            elif threat['threat_level'] == ThreatLevel.HIGH.value:
                report['high_threats'].append(threat)
        
        return report
    
    def print_summary(self):
        """Print threat summary to console"""
        report = self.generate_threat_report()
        self.logger.info("=" * 80)
        self.logger.info("COUNTER-HONEYPOT THREAT REPORT")
        self.logger.info("=" * 80)
        self.logger.info(json.dumps(report, indent=2))
        self.logger.info("=" * 80)


def main():
    """Main entry point with demonstrations"""
    honeypot = CounterHoneypotMulti()
    
    print("\n" + "="*80)
    print("COUNTER-HONEYPOT: Multi-Vector Threat Detection Demonstration")
    print("Purpose: Demonstrate the need to stop threat actors from exploiting systems")
    print("="*80 + "\n")
    
    # SSH Attack Simulations
    print("[*] Simulating SSH Attacks...")
    honeypot.simulate_ssh_attack("192.168.1.100", "root", "password")
    honeypot.simulate_ssh_attack("192.168.1.101", "admin", "123456")
    honeypot.simulate_ssh_attack("192.168.1.102", "testuser", "mysecurepass123")
    
    # WEB Attack Simulations
    print("[*] Simulating WEB Attacks...")
    honeypot.simulate_web_attack("192.168.1.200", "/login.php?user=admin' OR '1'='1")
    honeypot.simulate_web_attack("192.168.1.201", "/search?q=<script>alert('XSS')</script>")
    honeypot.simulate_web_attack("192.168.1.202", "/file.php?path=../../../../etc/passwd")
    
    # Database Attack Simulations
    print("[*] Simulating DATABASE Attacks...")
    honeypot.simulate_database_attack("192.168.1.150", "MySQL", 3306, "root", "")
    honeypot.simulate_database_attack("192.168.1.151", "PostgreSQL", 5432, "postgres", "password")
    honeypot.simulate_database_attack("192.168.1.152", "MSSQL", 1433, "sa", "")
    
    # Print report
    honeypot.print_summary()
    
    print("\n[+] Threat logs saved to: counter_honeypot.log")
    print("[+] All threats have been detected, logged, and can be analyzed for patterns\n")


if __name__ == '__main__':
    main()
