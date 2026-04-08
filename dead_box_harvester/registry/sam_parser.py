"""SAM hive parser for NTLM hash extraction"""

import logging
import re
from pathlib import Path
from typing import List, Dict, Any

from .parser import RegistryHiveParser


logger = logging.getLogger(__name__)


class SAMHiveParser(RegistryHiveParser):
    """Extract user account hashes from SAM hive"""

    def parse(self) -> Dict[str, Any]:
        """Parse SAM hive and extract NTLM hashes"""
        if not self.load_hive():
            return {"error": "Failed to load hive", "hashes": [], "valid": False}

        hashes = self.extract_user_hashes()

        return {
            "source": str(self.hive_path),
            "hashes": hashes,
            "valid": True,
            "hash_count": len(hashes)
        }

    def extract_user_hashes(self) -> List[Dict[str, Any]]:
        """Extract NTLM hashes from SAM"""
        hashes = []

        # Method 1: String extraction (fallback)
        strings = self.extract_strings(min_length=32)
        ntlm_pattern = re.compile(r'^[a-f0-9]{32}$', re.IGNORECASE)

        for s in strings:
            if ntlm_pattern.match(s):
                hash_upper = s.upper()
                if hash_upper != "00000000000000000000000000000000":
                    hashes.append({
                        "hash_type": "NTLM",
                        "hash": hash_upper,
                        "source": "SAM",
                        "decryption_required": False,
                        "cracking_format": f"Administrator:{hash_upper}",
                        "hashcat_mode": 1000
                    })

        # Deduplicate
        seen = set()
        unique_hashes = []
        for h in hashes:
            if h["hash"] not in seen:
                seen.add(h["hash"])
                unique_hashes.append(h)

        logger.info(f"Extracted {len(unique_hashes)} unique NTLM hashes from SAM")
        return unique_hashes
