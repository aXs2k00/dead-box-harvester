"""Cryptographic utilities for DPAPI operations"""

import logging
from typing import Optional


logger = logging.getLogger(__name__)


class DPAPICrypto:
    """DPAPI cryptographic operations"""

    @staticmethod
    def verify_aes_requirement():
        """Verify AES-256-GCM availability"""
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            logger.info("AES-256-GCM available for DPAPI decryption")
            return True
        except ImportError:
            logger.warning("AES-256-GCM not available. Install: pip install cryptography")
            return False

    @staticmethod
    def decrypt_aes_gcm(key: bytes, nonce: bytes, ciphertext: bytes, 
                       associated_data: Optional[bytes] = None) -> Optional[bytes]:
        """Decrypt data using AES-256-GCM"""
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            if len(key) != 32:
                logger.error(f"Invalid key size: {len(key)} (expected 32)")
                return None

            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)
            return plaintext
        except Exception as e:
            logger.error(f"AES-GCM decryption failed: {e}")
            return None
