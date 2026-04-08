"""SECURITY hive parser for LSA secrets extraction"""

import logging
from pathlib import Path
from typing import List, Dict, Any

from .parser import RegistryHiveParser


logger = logging.getLogger(__name__)


class SECURITYHiveParser(RegistryHiveParser):
    """Extract LSA secrets from SECURITY hive"""

    LSA_SECRET_NAMES = [
        b"DPAPI_SYSTEM",
        b"NL$KM",
        b"LSA_ADTP",
        b"LSA_PPTP",
        b"RasDialParams",
        b"RasMan",
        b"SAI",
        b"SC",
        b"SSO",
        b"WDigest",
    ]

    def parse(self) -> Dict[str, Any]:
        """Parse SECURITY hive and extract LSA secrets"""
        if not self.load_hive():
            return {"error": "Failed to load hive", "secrets": [], "valid": False}

        secrets = self.extract_lsa_secrets()

        return {
            "source": str(self.hive_path),
            "secrets": secrets,
            "valid": True,
            "secret_count": len(secrets)
        }

    def extract_lsa_secrets(self) -> List[Dict[str, Any]]:
        """Extract LSA secrets"""
        secrets = []

        for secret_name in self.LSA_SECRET_NAMES:
            if secret_name in self.hive_data:
                secrets.append({
                    "type": "LSA_SECRET",
                    "name": secret_name.decode('utf-8', errors='ignore'),
                    "encrypted": True,
                    "decryption_key": "SysKey (from SYSTEM hive)",
                    "extraction_status": "requires_syskey_decryption"
                })

        # Extract potential service account passwords
        strings = self.extract_strings(min_length=8)

        for s in strings:
            if (len(s) >= 8 and 
                any(c.isupper() for c in s) and 
                any(c.isdigit() for c in s) and
                any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in s)):

                secrets.append({
                    "type": "LSA_SECRET_CANDIDATE",
                    "value": s[:50],
                    "encrypted": True,
                    "confidence": "medium",
                    "decryption_key": "SysKey"
                })

        logger.info(f"Extracted {len(secrets)} LSA secrets/candidates")
        return secrets
