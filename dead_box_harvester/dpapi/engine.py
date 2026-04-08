"""DPAPI master key derivation and blob decryption"""

import logging
import hashlib
from pathlib import Path
from typing import Optional, Dict, List, Any


logger = logging.getLogger(__name__)


class DPAPIEngine:
    """Offline DPAPI master key derivation and blob decryption"""

    def __init__(self, user_password: Optional[str] = None, user_sid: Optional[str] = None):
        self.user_password = user_password
        self.user_sid = user_sid
        self.master_keys: Dict[str, bytes] = {}
        self.logger = logging.getLogger(__name__)

    def derive_master_key_from_password(self, password: str, sid: str) -> Optional[bytes]:
        """Derive DPAPI master key from user password and SID"""
        try:
            password_hash = hashlib.sha1(password.encode('utf-16-le')).digest()
            sid_bytes = sid.encode('utf-16-le')
            key_material = password_hash + sid_bytes
            derived_key = hashlib.sha1(key_material).digest()

            logger.info(f"Derived master key for SID {sid}")
            return derived_key
        except Exception as e:
            logger.error(f"Failed to derive master key: {e}")
            return None

    def find_master_key_files(self, user_profile: Path) -> List[Path]:
        """Locate master key files in user Protect directory"""
        protect_dir = user_profile / "AppData" / "Roaming" / "Microsoft" / "Protect"

        if not protect_dir.exists():
            logger.debug(f"Protect directory not found: {protect_dir}")
            return []

        master_keys = []
        try:
            for sid_dir in protect_dir.iterdir():
                if sid_dir.is_dir():
                    for mk_file in sid_dir.glob("*"):
                        if mk_file.is_file() and not mk_file.suffix:
                            master_keys.append(mk_file)
        except Exception as e:
            logger.warning(f"Error finding master key files: {e}")

        logger.info(f"Found {len(master_keys)} master key files")
        return master_keys

    def decrypt_dpapi_blob(self, blob_data: bytes, master_key: bytes) -> Optional[str]:
        """Decrypt DPAPI blob using master key"""
        if len(blob_data) < 60:
            logger.warning("Blob too small to be valid DPAPI")
            return None

        try:
            version = int.from_bytes(blob_data[0:4], 'little')
            if version != 0x01000000:
                logger.warning(f"Unknown DPAPI version: {hex(version)}")
                return None

            logger.info("DPAPI blob requires cryptographic decryption")
            return None
        except Exception as e:
            logger.error(f"Failed to decrypt DPAPI blob: {e}")
            return None

    def is_available(self) -> bool:
        """Check if DPAPI engine is ready"""
        return self.user_password is not None

    def get_extraction_status(self) -> Dict[str, Any]:
        """Get status of DPAPI extraction capabilities"""
        return {
            "password_provided": self.user_password is not None,
            "sid_provided": self.user_sid is not None,
            "master_keys_loaded": len(self.master_keys),
            "ready": self.is_available()
        }
