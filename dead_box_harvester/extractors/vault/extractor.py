"""Credential Manager vault extractor"""

import logging
import struct
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Dict, Any, Optional

from ..base import BaseExtractor


logger = logging.getLogger(__name__)


class CredentialManagerExtractor(BaseExtractor):
    """Extract credentials from Windows Credential Manager vault"""

    # Credential file types
    CRED_TYPE_GENERIC = 1
    CRED_TYPE_DOMAIN_PASSWORD = 2
    CRED_TYPE_DOMAIN_CERTIFICATE = 3
    CRED_TYPE_DOMAIN_VISIBLE_PASSWORD = 4
    CRED_TYPE_GENERIC_CERTIFICATE = 5
    CRED_TYPE_DOMAIN_EXTENDED = 6
    CRED_TYPE_WEB = 7
    CRED_TYPE_WINDOWS_PASSWORD = 8

    # Credential persistence
    CRED_PERSIST_SESSION = 1
    CRED_PERSIST_LOCAL_MACHINE = 2
    CRED_PERSIST_ENTERPRISE = 3

    # Known credential target patterns
    TARGET_PATTERNS = [
        "WindowsLive:target=",
        "SkyDrive:target=",
        "OneDrive:target=",
        "Skype:",
        "Outlook:",
        "MicrosoftAccount:",
    ]

    def __init__(self, dpapi_engine=None):
        super().__init__("Credential Manager")
        self.dpapi_engine = dpapi_engine

    def extract(self, user_profile: Path) -> List[Dict[str, Any]]:
        """Extract credentials from Credential Manager"""
        return self._extract_credentials(user_profile)

    def _extract_credentials(self, user_profile: Path) -> List[Dict[str, Any]]:
        """Extract credentials from vault and credentials directories"""
        credentials = []

        # Search common paths
        cred_paths = [
            user_profile / "AppData" / "Roaming" / "Microsoft" / "Credentials",
            user_profile / "AppData" / "Local" / "Microsoft" / "Vault",
            # Legacy paths
            user_profile / "AppData" / "Roaming" / "Microsoft" / "Protect",
        ]

        for cred_path in cred_paths:
            if cred_path.exists() and cred_path.is_dir():
                try:
                    for cred_file in cred_path.iterdir():
                        if cred_file.is_file():
                            cred_data = self._parse_credential_file(cred_file)
                            if cred_data:
                                credentials.append(cred_data)
                except Exception as e:
                    self.logger.debug(f"Error reading {cred_path}: {e}")

        # Also search in Vault directories (CRED_TYPE_WEB)
        vault_path = user_profile / "AppData" / "Local" / "Microsoft" / "Vault"
        if vault_path.exists():
            credentials.extend(self._parse_vault_directory(vault_path))

        # Try decryption
        self._decrypt_credentials(credentials)
        
        self.log_extraction(len(credentials), "Credential Manager entries")
        return credentials

    def _parse_vault_directory(self, vault_path: Path) -> List[Dict[str, Any]]:
        """Parse vault directory structure"""
        credentials = []
        
        try:
            for vault_file in vault_path.glob("*.vcrd"):
                cred = self._parse_vault_credential(vault_file)
                if cred:
                    credentials.append(cred)
        except Exception as e:
            self.logger.debug(f"Error parsing vault: {e}")
            
        return credentials

    def _parse_vault_credential(self, vault_file: Path) -> Optional[Dict[str, Any]]:
        """Parse .vcrd vault credential file"""
        try:
            with open(vault_file, 'rb') as f:
                data = f.read()
            
            if len(data) < 4:
                return None
                
            # Check for vault credential signature
            if data[:4] != b'VCRD':
                return None
                
            # Basic parsing - vault files are complex binary format
            # For now, return metadata
            return {
                "type": "vault_credential",
                "file": str(vault_file),
                "size": len(data),
                "encrypted": True,
                "decryption_status": "requires_dpapi"
            }
        except Exception as e:
            self.logger.debug(f"Error parsing vault file: {e}")
            return None

    def _parse_credential_file(self, cred_file: Path) -> Optional[Dict[str, Any]]:
        """Parse Windows credential file"""
        try:
            with open(cred_file, "rb") as f:
                data = f.read()

            if len(data) < 4:
                return None

            # Check for DPAPI blob signature (version 1)
            version = struct.unpack("<I", data[:4])[0]
            if version != 1:
                # Try to parse as generic file
                return {
                    "type": "unknown",
                    "file": str(cred_file),
                    "size": len(data),
                    "note": "Unknown credential format"
                }

            # Parse credential header
            # Structure (simplified):
            # 0-4: flags
            # 4-8: size
            # 8-16: type
            # 16-24: persistence
            # 24-32: attribute count
            # 32-40: blob size
            # 40-48: blob offset
            # 48+: target name (null-terminated string)
            
            if len(data) < 64:
                return {
                    "type": "dpapi_blob",
                    "file": str(cred_file),
                    "size": len(data),
                    "encrypted": True
                }

            # Extract basic info
            cred_type = struct.unpack("<I", data[8:12])[0]
            persistence = struct.unpack("<I", data[16:20])[0]
            blob_size = struct.unpack("<I", data[32:36])[0]
            blob_offset = struct.unpack("<I", data[40:44])[0]

            # Find target name (after header, typically at offset 48+)
            target_start = 48
            target_end = data.find(b'\x00', target_start)
            if target_end > target_start:
                target_name = data[target_start:target_end].decode('utf-16-le', errors='ignore')
            else:
                target_name = "Unknown"

            # Extract blob
            blob_data = data[blob_offset:blob_offset + blob_size] if blob_size > 0 else None

            cred = {
                "type": self._get_cred_type_name(cred_type),
                "target": target_name,
                "persistence": self._get_persistence_name(persistence),
                "file": str(cred_file),
                "encrypted_blob": blob_data.hex()[:64] + "..." if blob_data else None,
                "blob_size": blob_size,
                "encrypted": True
            }

            # Try to identify credential type from target name
            for pattern in self.TARGET_PATTERNS:
                if pattern.lower() in target_name.lower():
                    cred["service_type"] = pattern.rstrip(':')
                    break

            return cred

        except Exception as e:
            self.logger.debug(f"Error parsing credential file {cred_file}: {e}")
            return None

    def _get_cred_type_name(self, cred_type: int) -> str:
        """Map credential type to readable name"""
        type_map = {
            self.CRED_TYPE_GENERIC: "generic",
            self.CRED_TYPE_DOMAIN_PASSWORD: "domain_password",
            self.CRED_TYPE_DOMAIN_CERTIFICATE: "domain_certificate",
            self.CRED_TYPE_DOMAIN_VISIBLE_PASSWORD: "domain_visible_password",
            self.CRED_TYPE_GENERIC_CERTIFICATE: "generic_certificate",
            self.CRED_TYPE_DOMAIN_EXTENDED: "domain_extended",
            self.CRED_TYPE_WEB: "web",
            self.CRED_TYPE_WINDOWS_PASSWORD: "windows_password",
        }
        return type_map.get(cred_type, f"unknown_{cred_type}")

    def _get_persistence_name(self, persistence: int) -> str:
        """Map persistence to readable name"""
        persist_map = {
            self.CRED_PERSIST_SESSION: "session",
            self.CRED_PERSIST_LOCAL_MACHINE: "local_machine",
            self.CRED_PERSIST_ENTERPRISE: "enterprise",
        }
        return persist_map.get(persistence, f"unknown_{persistence}")

    def _decrypt_credentials(self, credentials: List[Dict[str, Any]]) -> None:
        """Attempt to decrypt credential blobs"""
        if not self.dpapi_engine or not self.dpapi_engine.is_available():
            for cred in credentials:
                if cred.get("encrypted"):
                    cred["decryption_status"] = "requires_password"
                    cred["password"] = None
            return

        for cred in credentials:
            if not cred.get("encrypted_blob"):
                cred["decryption_status"] = "no_blob"
                continue

            # Note: Full decryption requires Windows API
            # This is a limitation of offline forensics
            cred["decryption_status"] = "requires_windows_api"
            cred["password"] = None