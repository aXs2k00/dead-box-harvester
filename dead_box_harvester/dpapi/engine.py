"""DPAPI master key derivation and blob decryption"""

import logging
import hashlib
import struct
from pathlib import Path
from typing import Optional, Dict, List, Any


logger = logging.getLogger(__name__)


class DPAPIEngine:
    """Offline DPAPI master key derivation and blob decryption"""

    def __init__(self, user_password: Optional[str] = None, user_sid: Optional[str] = None):
        self.user_password = user_password
        self.user_sid = user_sid
        self.derived_master_key: Optional[bytes] = None
        self.master_keys: Dict[str, bytes] = {}
        
        # Derive master key if password provided
        if user_password and user_sid:
            self.derived_master_key = self.derive_master_key_from_password(user_password, user_sid)

    def derive_master_key_from_password(self, password: str, sid: str) -> Optional[bytes]:
        """Derive DPAPI master key from user password and SID"""
        try:
            # Windows DPAPI uses: SHA1(password as UTF-16-LE + SID)
            password_bytes = password.encode('utf-16-le')
            sid_bytes = sid.encode('utf-16-le')
            key_material = password_bytes + sid_bytes
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
                if sid_dir.is_dir() and sid_dir.name not in ['.', '..']:
                    for mk_file in sid_dir.glob("*"):
                        if mk_file.is_file() and not mk_file.suffix and not mk_file.name.startswith('.'):
                            master_keys.append(mk_file)
        except Exception as e:
            logger.warning(f"Error finding master key files: {e}")

        logger.info(f"Found {len(master_keys)} master key files")
        return master_keys

    def decrypt_dpapi_blob(self, blob_data: bytes, entropy: Optional[bytes] = None) -> Optional[bytes]:
        """Decrypt DPAPI blob using derived master key"""
        if not self.derived_master_key:
            logger.warning("No master key available - password not provided")
            return None
            
        if len(blob_data) < 60:
            logger.warning("Blob too small to be valid DPAPI")
            return None

        try:
            # DPAPI blob structure:
            # 0-4: version (0x01000000)
            # 4-8: provider GUID (16 bytes, but starts at 4)
            # 20-24: algorithm ID
            # 24-28: cipher mode
            # 28-32: reserved
            # 32-48: HMAC-SHA256 of plaintext
            # 48-60: IV (12 bytes for GCM)
            # 60+: encrypted data + 16 byte auth tag
            
            version = int.from_bytes(blob_data[0:4], 'little')
            if version != 0x01000000:
                logger.warning(f"Unknown DPAPI version: {hex(version)}")
                return None
            
            # For now, we can parse but can't decrypt without Windows API
            # The actual decryption requires CryptUnprotectData
            # This is a limitation of offline forensics
            logger.debug(f"DPAPI blob version: {version:#x}, size: {len(blob_data)}")
            
            # Try basic AES decryption (works for some older configs)
            return self._try_aes_decrypt(blob_data, entropy)
            
        except Exception as e:
            logger.error(f"Failed to decrypt DPAPI blob: {e}")
            return None

    def _try_aes_decrypt(self, blob_data: bytes, entropy: Optional[bytes] = None) -> Optional[bytes]:
        """Attempt AES decryption of DPAPI blob"""
        if len(blob_data) < 60:
            return None
            
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend
            
            # Extract IV (bytes 48-60, 12 bytes) and ciphertext
            iv = blob_data[48:60]
            # Encrypted data starts at 60, auth tag is last 16 bytes
            encrypted = blob_data[60:-16]
            auth_tag = blob_data[-16:]
            
            # Build decryption key with optional entropy
            key = self.derived_master_key
            if entropy:
                key = hashlib.sha1(self.derived_master_key + entropy).digest()
            
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(encrypted) + decryptor.finalize()
            
            return plaintext
            
        except ImportError:
            logger.warning("cryptography library not available")
            return None
        except Exception as e:
            logger.debug(f"AES decryption failed: {e}")
            return None

    def decrypt_wifi_key(self, encrypted_key: str) -> Optional[str]:
        """Decrypt WiFi profile key material"""
        if not encrypted_key:
            return None
            
        try:
            import base64
            encrypted_bytes = base64.b64decode(encrypted_key)
            decrypted = self.decrypt_dpapi_blob(encrypted_bytes)
            if decrypted:
                # Remove padding
                pad_len = decrypted[-1]
                if pad_len <= 16:
                    return decrypted[:-pad_len].decode('utf-16-le', errors='ignore')
        except Exception as e:
            logger.debug(f"WiFi key decryption failed: {e}")
            
        return None

    def is_available(self) -> bool:
        """Check if DPAPI engine is ready"""
        return self.derived_master_key is not None

    def get_extraction_status(self) -> Dict[str, Any]:
        """Get status of DPAPI extraction capabilities"""
        return {
            "password_provided": self.user_password is not None,
            "sid_provided": self.user_sid is not None,
            "master_keys_loaded": len(self.master_keys),
            "key_derived": self.derived_master_key is not None,
            "ready": self.is_available()
        }