"""File-based credential scanner using regex patterns"""

import logging
import re
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from .base import BaseExtractor


logger = logging.getLogger(__name__)


@dataclass
class CredentialPattern:
    """Credential pattern definition"""
    name: str
    pattern: str
    confidence: float
    category: str  # api_key, password, token, key, etc.


class CredentialFileScanner(BaseExtractor):
    """Scan files for hardcoded credentials using regex patterns"""
    
    # Comprehensive credential patterns
    PATTERNS = [
        # AWS
        CredentialPattern("aws_access_key", r"AKIA[0-9A-Z]{16}", 0.99, "api_key"),
        CredentialPattern("aws_secret_key", r"(?i)(aws_secret_access_key|aws_secret_key|AWS_SECRET)[\s]*[=:]+[\s]*['\"]?([a-zA-Z0-9/+=]{40})", 0.95, "api_key"),
        CredentialPattern("aws_session_token", r"(?i)aws_session_token[\s]*[=:]+[\s]*['\"]?([a-zA-Z0-9/+=]{100,})", 0.90, "token"),
        
        # Generic API keys
        CredentialPattern("api_key_generic", r"(?i)(api[_-]?key|apikey)[\s]*[=:]+[\s]*['\"]?([a-zA-Z0-9_\-]{20,})", 0.75, "api_key"),
        CredentialPattern("api_secret", r"(?i)(api[_-]?secret|apisecret)[\s]*[=:]+[\s]*['\"]?([a-zA-Z0-9_\-]{20,})", 0.75, "api_key"),
        
        # Database connection strings
        CredentialPattern("mysql_conn", r"(?i)mysql://[^:]+:[^@]+@", 0.85, "connection_string"),
        CredentialPattern("postgres_conn", r"(?i)postgresql://[^:]+:[^@]+@", 0.85, "connection_string"),
        CredentialPattern("mongo_conn", r"(?i)mongodb(\+srv)?://[^:]+:[^@]+@", 0.85, "connection_string"),
        CredentialPattern("redis_conn", r"(?i)redis://[^:]+:[^@]+@", 0.85, "connection_string"),
        CredentialPattern("mssql_conn", r"(?i)Server=[^;]+;Database=[^;]+;User Id=[^;]+;Password=[^;]+", 0.85, "connection_string"),
        
        # Tokens
        CredentialPattern("github_token", r"ghp_[a-zA-Z0-9]{36}", 0.99, "token"),
        CredentialPattern("github_oauth", r"gho_[a-zA-Z0-9]{36}", 0.99, "token"),
        CredentialPattern("gitlab_token", r"glpat-[a-zA-Z0-9\-]{20,}", 0.99, "token"),
        CredentialPattern("slack_token", r"xox[baprs]-[a-zA-Z0-9\-]+", 0.99, "token"),
        CredentialPattern("slack_webhook", r"https://hooks\.slack\.com/services/T[a-zA-Z0-9]+/B[a-zA-Z0-9]+/[a-zA-Z0-9]+", 0.95, "webhook"),
        CredentialPattern("discord_token", r"[MN][a-zA-Z0-9]{23,}\.[a-zA-Z0-9\-_]{6}\.[a-zA-Z0-9\-_]{27}", 0.99, "token"),
        CredentialPattern("telegram_token", r"\d{8,10}:[a-zA-Z0-9_\-]{35}", 0.95, "token"),
        
        # Private keys
        CredentialPattern("rsa_private_key", r"-----BEGIN RSA PRIVATE KEY-----", 0.99, "private_key"),
        CredentialPattern("ec_private_key", r"-----BEGIN EC PRIVATE KEY-----", 0.99, "private_key"),
        CredentialPattern("dsa_private_key", r"-----BEGIN DSA PRIVATE KEY-----", 0.99, "private_key"),
        CredentialPattern("openssh_key", r"-----BEGIN OPENSSH PRIVATE KEY-----", 0.99, "private_key"),
        CredentialPattern("pem_cert", r"-----BEGIN CERTIFICATE-----", 0.90, "certificate"),
        
        # Generic passwords in configs
        CredentialPattern("password_assignment", r"(?i)(password|passwd|pwd)[\s]*[=:]+[\s]*['\"]?([^\s'\"]{4,})", 0.70, "password"),
        CredentialPattern("secret_assignment", r"(?i)(secret|token)[\s]*[=:]+[\s]*['\"]?([^\s'\"]{8,})", 0.70, "secret"),
        
        # Environment variables
        CredentialPattern("env_password", r"(?i)(PASSWORD|SECRET|API_KEY|TOKEN)[\s]*=[\s]*['\"]?([a-zA-Z0-9_\-]{8,})", 0.65, "env_var"),
        
        # SSH config
        CredentialPattern("ssh_key_file", r"(?i)(IdentityFile|PrivateKey)[\s]+", 0.80, "ssh"),
        
        # JWT tokens
        CredentialPattern("jwt_token", r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*", 0.90, "token"),
        
        # Stripe keys
        CredentialPattern("stripe_key", r"(sk|pk)_(test|live)_[a-zA-Z0-9]{24,}", 0.99, "api_key"),
        
        # Twilio
        CredentialPattern("twilio_key", r"SK[a-f0-9]{32}", 0.95, "api_key"),
        
        # SendGrid
        CredentialPattern("sendgrid_key", r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}", 0.95, "api_key"),
        
        # Azure
        CredentialPattern("azure_key", r"[a-zA-Z0-9+/]{86}==", 0.80, "api_key"),
        CredentialPattern("azure_conn", r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+", 0.90, "connection_string"),
        
        # Heroku
        CredentialPattern("heroku_key", r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}", 0.85, "api_key"),
        
        # NPM/token
        CredentialPattern("npm_token", r"npm_[a-zA-Z0-9]{36}", 0.95, "token"),
    ]
    
    # File extensions to scan
    SCAN_EXTENSIONS = {
        '.py', '.js', '.ts', '.json', '.yml', '.yaml', '.xml', '.conf', '.ini',
        '.cfg', '.config', '.properties', '.env', '.txt', '.sh', '.bat', '.ps1',
        '.sql', '.rb', '.go', '.rs', '.java', '.cs', '.php', '.asp', '.aspx',
        '.htm', '.html', '.md', '.log', '.key', '.pem', '.cert', '.crt'
    }
    
    # Directories to skip
    SKIP_DIRS = {
        'node_modules', '.git', '.svn', '__pycache__', 'venv', 'env', '.venv',
        'build', 'dist', 'target', '.idea', '.vscode', 'bin', 'obj'
    }
    
    # Max file size to scan (5MB)
    MAX_FILE_SIZE = 5 * 1024 * 1024
    
    def __init__(self, mount_point: Path):
        super().__init__(mount_point)
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Compile regex patterns for efficiency"""
        self.compiled_patterns = []
        for cred in self.PATTERNS:
            try:
                compiled = re.compile(cred.pattern)
                self.compiled_patterns.append((cred, compiled))
            except re.error as e:
                logger.warning(f"Invalid regex pattern {cred.name}: {e}")
    
    def extract(self) -> List[Dict[str, Any]]:
        """Scan all files in backup for credentials"""
        return self.scan_all()
    
    def scan_all(self) -> List[Dict[str, Any]]:
        """Scan entire backup for credential patterns"""
        findings = []
        
        if not self.mount_point.exists():
            logger.warning(f"Mount point does not exist: {self.mount_point}")
            return findings
        
        logger.info(f"Scanning {self.mount_point} for hardcoded credentials...")
        
        files_scanned = 0
        
        try:
            for file_path in self.mount_point.rglob('*'):
                if not file_path.is_file():
                    continue
                
                # Skip binary files and large files
                try:
                    if file_path.stat().st_size > self.MAX_FILE_SIZE:
                        continue
                except:
                    continue
                
                # Skip based on path
                if self._should_skip(file_path):
                    continue
                
                # Only scan text files
                if file_path.suffix.lower() not in self.SCAN_EXTENSIONS:
                    continue
                
                # Scan file
                file_findings = self._scan_file(file_path)
                findings.extend(file_findings)
                files_scanned += 1
                
                if files_scanned % 100 == 0:
                    logger.debug(f"Scanned {files_scanned} files...")
                    
        except Exception as e:
            logger.error(f"Error during credential scanning: {e}")
        
        logger.info(f"Scanned {files_scanned} files, found {len(findings)} credentials")
        return findings
    
    def _should_skip(self, file_path: Path) -> bool:
        """Check if file should be skipped"""
        parts = file_path.parts
        for skip_dir in self.SKIP_DIRS:
            if skip_dir in parts:
                return True
        return False
    
    def _scan_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """Scan individual file for credential patterns"""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception:
            return findings
        
        for cred_pattern, compiled in self.compiled_patterns:
            try:
                for match in compiled.finditer(content):
                    # Get surrounding context
                    start = max(0, match.start() - 30)
                    end = min(len(content), match.end() + 30)
                    context = content[start:end].replace('\n', ' ')
                    
                    finding = {
                        "type": cred_pattern.name,
                        "category": cred_pattern.category,
                        "confidence": cred_pattern.confidence,
                        "file": str(file_path.relative_to(self.mount_point)),
                        "line_hint": content[:match.start()].count('\n') + 1,
                        "value": self._sanitize_value(match.group(), cred_pattern.name),
                        "context": f"...{context}..."
                    }
                    findings.append(finding)
            except Exception:
                continue
        
        return findings
    
    def _sanitize_value(self, value: str, pattern_name: str) -> str:
        """Sanitize found credential value for output"""
        # For private keys/certs, just indicate type
        if "private_key" in pattern_name or "cert" in pattern_name:
            return f"[{pattern_name} found]"
        
        # For connection strings, mask password
        if "conn" in pattern_name.lower():
            return re.sub(r':([^@]+)@', ':****@', value)
        
        # For other values, truncate
        if len(value) > 50:
            return value[:50] + "..."
        
        return value


def scan_for_credentials(backup_path: Path) -> List[Dict[str, Any]]:
    """Convenience function to scan backup for credentials"""
    scanner = CredentialFileScanner(backup_path)
    return scanner.scan_all()