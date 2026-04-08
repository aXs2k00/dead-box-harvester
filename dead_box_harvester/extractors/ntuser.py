"""NTUSER.DAT parser for user-specific registry artifacts"""

import logging
import re
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from .base import BaseExtractor


logger = logging.getLogger(__name__)


@dataclass
class NTUSERArtifact:
    """NTUSER registry artifact"""
    key_path: str
    value_name: str
    value_data: str
    artifact_type: str
    forensic_value: str


class NTUSERParser(BaseExtractor):
    """Parse NTUSER.DAT for user-specific forensic artifacts"""
    
    # Key paths with high forensic value
    FORENSIC_KEYS = {
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer": {
            "RunMRU": "recent_commands",
            "ComDlg32": "file_dialog_history", 
            "ShellBags": "shell_bags",
            "RecentDocs": "recent_documents",
        },
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run": {
            "_default": "auto_run_programs",
        },
        "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce": {
            "_default": "run_once_programs",
        },
        "Software\\Microsoft\\Windows\\Shell\\BagMRU": {
            "_default": "explorer_bags",
        },
        "Software\\Microsoft\\Windows\\Shell\\Bags": {
            "_default": "explorer_folders",
        },
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts": {
            "_default": "file_associations",
        },
        "Software\\Classes": {
            "_default": "file_type_associations",
        },
        "Software\\Microsoft\\Windows\\CurrentVersion\\Applets": {
            "_default": "applet_settings",
        },
        "Environment": {
            "_default": "environment_variables",
        },
        "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings": {
            "_default": "browser_proxy_settings",
        },
        "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall": {
            "_default": "installed_programs",
        },
    }
    
    def __init__(self, mount_point: Path):
        super().__init__("NTUSER Parser")
        self.mount_point = mount_point
    
    def find_ntuser_files(self) -> List[Path]:
        """Find all NTUSER.DAT files in user profiles"""
        ntuser_files = []
        
        users_path = self.mount_point / "Users"
        if not users_path.exists():
            logger.warning(f"Users directory not found: {users_path}")
            return ntuser_files
        
        for user_dir in users_path.iterdir():
            if not user_dir.is_dir():
                continue
            
            # Skip system directories
            if user_dir.name in ['Public', 'Default', 'Default User', 'All Users']:
                continue
            
            # Primary NTUSER.DAT
            ntuser = user_dir / "NTUSER.DAT"
            if ntuser.exists():
                ntuser_files.append(ntuser)
                logger.log_artifact("ntuser_dat", str(ntuser))
            
            # NTUSER.DAT.LOG1 (transaction log)
            ntuser_log = user_dir / "NTUSER.DAT.LOG1"
            if ntuser_log.exists():
                ntuser_files.append(ntuser_log)
                
        logger.info(f"Found {len(ntuser_files)} NTUSER files")
        return ntuser_files
    
    def extract(self) -> List[Dict[str, Any]]:
        """Extract artifacts from all NTUSER files"""
        return self._extract_all()
    
    def _extract_all(self) -> List[Dict[str, Any]]:
        """Extract all NTUSER artifacts"""
        artifacts = []
        
        ntuser_files = self.find_ntuser_files()
        
        for ntuser_path in ntuser_files:
            file_artifacts = self._parse_ntuser_file(ntuser_path)
            artifacts.extend(file_artifacts)
        
        self.log_extraction(len(artifacts), "NTUSER artifacts")
        return artifacts
    
    def _parse_ntuser_file(self, ntuser_path: Path) -> List[Dict[str, Any]]:
        """Parse single NTUSER.DAT file"""
        artifacts = []
        username = ntuser_path.parent.name
        
        try:
            with open(ntuser_path, 'rb') as f:
                data = f.read()
        except Exception as e:
            logger.warning(f"Cannot read {ntuser_path}: {e}")
            return artifacts
        
        logger.debug(f"Parsing NTUSER.DAT for user: {username}")
        
        # Extract ASCII strings
        ascii_strings = self._extract_strings(data, encoding='ascii')
        # Extract Unicode strings
        unicode_strings = self._extract_strings(data, encoding='utf-16-le')
        
        # Combine both
        all_strings = list(set(ascii_strings + unicode_strings))
        
        # Extract key artifacts
        artifacts.extend(self._extract_recent_documents(all_strings, username))
        artifacts.extend(self._extract_run_commands(all_strings, username))
        artifacts.extend(self._extract_shell_bags(all_strings, username))
        artifacts.extend(self._extract_environment_vars(all_strings, username))
        artifacts.extend(self._extract_network_places(all_strings, username))
        artifacts.extend(self._extract_usb_history(all_strings, username))
        
        return artifacts
    
    def _extract_strings(self, data: bytes, encoding: str) -> List[str]:
        """Extract strings from binary data"""
        strings = []
        min_len = 4
        
        if encoding == 'ascii':
            pattern = rb'[\x20-\x7e]{' + str(min_len).encode() + rb',}'
            for match in re.finditer(pattern, data):
                try:
                    s = match.group().decode('ascii')
                    strings.append(s)
                except:
                    pass
        else:
            # UTF-16-LE (double-byte ASCII)
            pattern = rb'(?:[\x20-\x7e]\x00){' + str(min_len).encode() + rb',}'
            for match in re.finditer(pattern, data):
                try:
                    s = match.group().decode('utf-16-le')
                    strings.append(s)
                except:
                    pass
        
        return strings
    
    def _extract_recent_documents(self, strings: List[str], username: str) -> List[Dict[str, Any]]:
        """Extract recent document references"""
        artifacts = []
        
        # Look for document extensions
        doc_patterns = [
            r'[A-Za-z]:\\[^\\\s]+\.(?:docx?|xlsx?|pptx?|pdf|txt|rtf)',
            r'\\\\[^\\\s]+[^\\\s]*',
        ]
        
        recent_files = []
        for s in strings:
            for pattern in doc_patterns:
                if re.match(pattern, s) and len(s) > 10:
                    recent_files.append(s)
        
        # Deduplicate and limit
        recent_files = list(set(recent_files))[:50]
        
        for filepath in recent_files:
            artifacts.append({
                "type": "recent_document",
                "user": username,
                "value": filepath[:200],
                "source": "NTUSER.DAT",
                "key_path": "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs"
            })
        
        return artifacts
    
    def _extract_run_commands(self, strings: List[str], username: str) -> List[Dict[str, Any]]:
        """Extract Run/RunOnce commands"""
        artifacts = []
        
        # Common executable paths and commands
        run_patterns = [
            r'[A-Za-z]:\\Program Files\\[^.]+\.exe',
            r'[A-Za-z]:\\Program Files \(x86\)\\[^.]+\.exe',
            r'[A-Za-z]:\\Users\\[^\\]+\\AppData\\Roaming\\[^.]+\.exe',
            r'cmd\.exe.*',
            r'powershell\.exe.*',
            r'schtasks\.exe.*',
            r'reg\.exe.*',
        ]
        
        for s in strings:
            for pattern in run_patterns:
                if re.match(pattern, s, re.IGNORECASE):
                    artifacts.append({
                        "type": "auto_run",
                        "user": username,
                        "value": s[:300],
                        "source": "NTUSER.DAT",
                        "key_path": "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
                    })
                    break
        
        return artifacts[:20]
    
    def _extract_shell_bags(self, strings: List[str], username: str) -> List[Dict[str, Any]]:
        """Extract Shell Bag artifacts (folder views)"""
        artifacts = []
        
        # Shell bags contain folder paths
        folder_patterns = [
            r'[A-Za-z]:\\Users\\[^\\]+',
            r'\\\\[^\\\s]+',
            r'::{[a-f0-9-]+}',
        ]
        
        folders = []
        for s in strings:
            for pattern in folder_patterns:
                if re.match(pattern, s) and len(s) > 5:
                    folders.append(s)
        
        folders = list(set(folders))[:30]
        
        for folder in folders:
            artifacts.append({
                "type": "shell_bag",
                "user": username,
                "value": folder[:200],
                "source": "NTUSER.DAT", 
                "key_path": "Software\\Microsoft\\Windows\\Shell\\BagMRU"
            })
        
        return artifacts
    
    def _extract_environment_vars(self, strings: List[str], username: str) -> List[Dict[str, Any]]:
        """Extract user environment variables"""
        artifacts = []
        
        # Look for PATH patterns
        for s in strings:
            if 'PATH=' in s.upper() or 'TEMP=' in s.upper() or 'TMP=' in s.upper():
                if len(s) > 10 and len(s) < 1000:
                    var_name = s.split('=')[0] if '=' in s else "UNKNOWN"
                    artifacts.append({
                        "type": "environment_variable",
                        "user": username,
                        "name": var_name,
                        "value": s[:300],
                        "source": "NTUSER.DAT",
                        "key_path": "Environment"
                    })
        
        return artifacts
    
    def _extract_network_places(self, strings: List[str], username: str) -> List[Dict[str, Any]]:
        """Extract network place references"""
        artifacts = []
        
        # UNC paths
        unc_pattern = r'\\\\[a-zA-Z0-9\-\.]+[a-zA-Z0-9\-\.\\]+'
        
        for s in strings:
            if re.match(unc_pattern, s):
                artifacts.append({
                    "type": "network_place",
                    "user": username,
                    "value": s[:200],
                    "source": "NTUSER.DAT",
                    "key_path": "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\NetworkPlaces"
                })
        
        return artifacts[:20]
    
    def _extract_usb_history(self, strings: List[str], username: str) -> List[Dict[str, Any]]:
        """Extract USB device history"""
        artifacts = []
        
        # Look for USB device patterns
        usb_patterns = [
            r'USBSTOR\\',
            r'##?#',
        ]
        
        for s in strings:
            for pattern in usb_patterns:
                if pattern in s:
                    artifacts.append({
                        "type": "usb_device",
                        "user": username,
                        "value": s[:200],
                        "source": "NTUSER.DAT",
                        "key_path": "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMru"
                    })
        
        return artifacts


def parse_ntuser(mount_point: Path) -> List[Dict[str, Any]]:
    """Convenience function to parse NTUSER files"""
    parser = NTUSERParser(mount_point)
    return parser.extract()