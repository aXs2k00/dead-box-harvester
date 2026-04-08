"""Firefox credential extractor"""

import json
import logging
from pathlib import Path
from typing import List, Dict, Any

from .base import BaseBrowserExtractor


logger = logging.getLogger(__name__)


class FirefoxCredentialExtractor(BaseBrowserExtractor):
    """Extract Firefox credentials from logins.json"""

    def __init__(self, dpapi_engine=None):
        super().__init__("Firefox", dpapi_engine)

    def _extract_credentials(self, profile_path: Path) -> List[Dict[str, Any]]:
        """Extract credentials from Firefox logins.json"""
        credentials = []

        logins_json = profile_path / "logins.json"
        if not logins_json.exists():
            self.logger.debug(f"logins.json not found: {logins_json}")
            return credentials

        try:
            with open(logins_json, 'r', encoding='utf-8') as f:
                data = json.load(f)

            for login in data.get("logins", []):
                credentials.append({
                    "browser": "Firefox",
                    "profile": profile_path.name,
                    "origin": login.get("hostname", ""),
                    "username": login.get("username", ""),
                    "password": login.get("encryptedPassword", ""),
                    "password_encrypted": True,
                    "encryption_type": "NSS (3DES/AES)",
                    "timePasswordChanged": login.get("timePasswordChanged"),
                    "decryption_status": "requires_nss_decryption_or_master_password",
                    "source_file": str(logins_json)
                })

            self.log_extraction(len(credentials), "Firefox credentials")
        except Exception as e:
            self.logger.warning(f"Failed to extract Firefox credentials: {e}")

        return credentials
