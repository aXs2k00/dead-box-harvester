"""Hashcat format exporter"""

import logging
from pathlib import Path
from typing import List, Dict

from .base import BaseExporter


logger = logging.getLogger(__name__)


class HashcatExporter(BaseExporter):
    """Export hashes in hashcat format"""

    def export(self, hashes: List[Dict[str, str]], filename: str = "hashes.txt") -> Path:
        """Save hashes in hashcat format"""
        output_file = self.output_dir / filename

        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                for hash_entry in hashes:
                    username = hash_entry.get('username', 'UNKNOWN')
                    hash_value = hash_entry.get('hash', '')
                    f.write(f"{username}:{hash_value}\n")

            self.logger.info(f"Saved hashcat format: {output_file}")
            return output_file
        except Exception as e:
            self.logger.error(f"Hashcat export failed: {e}")
            raise
