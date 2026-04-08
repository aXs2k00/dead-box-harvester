"""Credential Manager vault extractor"""

import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

from ..base import BaseExtractor


logger = logging.getLogger(__name__)


class CredentialManagerExtractor(BaseExtractor):
    """Extract credentials from Windows Credential Manager vault"""

    def __init__(self, dpapi_engine=None):
        super().__init__("Credential Manager")
        self.dpapi_engine = dpapi_engine

    def extract(self, user_profile: Path) -> List[Dict[str, Any]]:
        """Extract credentials from Credential Manager"""
        return self._extract_credentials(user_profile)

    def _extract_credentials(self, user_profile: Path) -> List[Dict[str, Any]]:
        """Extract credentials from vault"""
        credentials = []

        cred_paths = [
            user_profile / "AppData" / "Roaming" / "Microsoft" / "Credentials",
            user_profile / "AppData" / "Local" / "Microsoft" / "Vault",
        ]

        for cred_path in cred_paths:
            if cred_path.exists():
                try:
                    for cred_file in cred_path.iterdir():
                        if cred_file.is_file():
                            cred_data = self._parse_credential_file(cred_file)
                            if cred_data:
                                credentials.append(cred_data)
                except Exception as e:
                    self.logger.debug(f"Error reading {cred_path}: {e}")

        self.log_extraction(len(credentials), "Credential Manager entries")
        return credentials

    def _parse_credential_file(self, cred_file: Path) -> Optional[Dict[str, Any]]:
        """Parse individual credential file"""
        try:
            with open(cred_file, "rb") as f:
                data = f.read()

            if len(data) >= 4:
                version = int.from_bytes(data[:4], "little")
                if version == 1:  # DPAPI blob signature
                    return {
                        "type": "DPAPI_BLOB",
                        "file": str(cred_file),
                        "size": len(data),
                        "encrypted": True,
                        "decryption_type": "DPAPI_master_key",
                        "decryption_status": "requires_master_key_decryption"
                    }
        except Exception as e:
            self.logger.debug(f"Error parsing credential file {cred_file}: {e}")

        return None
