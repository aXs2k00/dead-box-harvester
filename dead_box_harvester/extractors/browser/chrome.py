"""Chrome/Edge/Brave credential extractor"""

import logging
import sqlite3
import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime

from .base import BaseBrowserExtractor


logger = logging.getLogger(__name__)


class ChromeCredentialExtractor(BaseBrowserExtractor):
    """Extract Chrome/Edge/Brave credentials from Login Data"""

    def __init__(self, dpapi_engine=None):
        super().__init__("Chrome/Edge/Brave", dpapi_engine)
        self.app_bound_detected = False

    def _extract_credentials(self, profile_path: Path) -> List[Dict[str, Any]]:
        """Extract credentials from Chrome Login Data"""
        credentials = []

        login_data = profile_path / "Login Data"
        if not login_data.exists():
            self.logger.debug(f"Login Data not found: {login_data}")
            return credentials

        # Check for App-Bound encryption (Chrome 127+)
        local_state = profile_path.parent / "Local State"
        if local_state.exists():
            self._check_app_bound_encryption(local_state)

        try:
            conn = sqlite3.connect(f"file:{login_data}?mode=ro", uri=True)
            cursor = conn.cursor()

            cursor.execute("""
                SELECT origin_url, username_value, password_value, 
                       date_created, date_last_used, times_used
                FROM logins
                WHERE blacklisted_by_user = 0
            """)

            for row in cursor.fetchall():
                origin_url, username, encrypted_password, date_created, date_last_used, times_used = row

                encryption_type = self._detect_encryption_type(encrypted_password)

                credential = {
                    "browser": "Chrome/Edge/Brave",
                    "profile": profile_path.name,
                    "origin": origin_url or "",
                    "username": username or "",
                    "password": "[encrypted]" if encrypted_password else "",
                    "password_encrypted": bool(encrypted_password),
                    "encryption_type": encryption_type,
                    "date_created": self._chrome_time_to_iso(date_created),
                    "date_last_used": self._chrome_time_to_iso(date_last_used),
                    "times_used": times_used or 0,
                    "decryption_status": self._get_decryption_status(encryption_type),
                    "source_file": str(login_data)
                }

                if isinstance(encrypted_password, bytes):
                    credential["password_hex"] = encrypted_password.hex()

                credentials.append(credential)

            conn.close()
            self.log_extraction(len(credentials), "Chrome credentials")

        except Exception as e:
            self.logger.warning(f"Failed to extract Chrome credentials: {e}")

        return credentials

    def _detect_encryption_type(self, encrypted_password: bytes) -> str:
        """Detect encryption type from blob structure"""
        if not encrypted_password:
            return "plaintext"

        if len(encrypted_password) > 4:
            version = encrypted_password[0]
            if version >= 20:
                self.app_bound_detected = True
                return "App-Bound (v20+ - NOT decryptable offline)"

        if len(encrypted_password) >= 4 and encrypted_password[:4] == b'\x01\x00\x00\x00':
            return "DPAPI (legacy - decryptable with password)"

        return "unknown"

    def _get_decryption_status(self, encryption_type: str) -> str:
        """Get human-readable decryption status"""
        if "App-Bound" in encryption_type:
            return "REQUIRES LIVE SYSTEM - Chrome 127+ App-Bound encryption cannot be decrypted offline"
        elif "DPAPI" in encryption_type:
            if self.dpapi_engine and self.dpapi_engine.is_available():
                return "decryptable with provided password"
            else:
                return "requires --password for DPAPI decryption"
        else:
            return "unknown encryption"

    def _check_app_bound_encryption(self, local_state: Path) -> bool:
        """Check if browser uses App-Bound encryption"""
        try:
            with open(local_state, 'r', encoding='utf-8') as f:
                data = json.load(f)

            os_crypt = data.get("os_crypt", {})
            if "app_bound_encrypted" in os_crypt:
                self.app_bound_detected = True
                self.logger.warning("App-Bound encryption detected - credentials cannot be decrypted offline")
                return True

            return False
        except Exception as e:
            self.logger.debug(f"Could not check App-Bound status: {e}")
            return False

    @staticmethod
    def _chrome_time_to_iso(chrome_time: int) -> Optional[str]:
        """Convert Chrome timestamp to ISO format"""
        if not chrome_time:
            return None

        try:
            unix_time = (chrome_time / 1000000) - 11644473600
            return datetime.fromtimestamp(unix_time).isoformat()
        except:
            return None
