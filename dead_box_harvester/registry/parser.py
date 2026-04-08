"""Base registry hive parser"""

import logging
import re
from pathlib import Path
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional


logger = logging.getLogger(__name__)


class RegistryHiveParser(ABC):
    """Base class for registry hive parsing"""

    HIVE_SIGNATURE = b'regf'

    def __init__(self, hive_path: Path):
        self.hive_path = hive_path
        self.hive_data: Optional[bytes] = None

    def load_hive(self) -> bool:
        """Load hive file into memory"""
        try:
            with open(self.hive_path, 'rb') as f:
                self.hive_data = f.read()

            if not self.hive_data.startswith(self.HIVE_SIGNATURE):
                logger.error(f"Invalid hive signature: {self.hive_path}")
                return False

            logger.info(f"Loaded hive: {self.hive_path} ({len(self.hive_data)} bytes)")
            return True
        except Exception as e:
            logger.error(f"Failed to load hive {self.hive_path}: {e}")
            return False

    def extract_strings(self, min_length: int = 4) -> List[str]:
        """Extract ASCII and Unicode strings from hive"""
        if not self.hive_data:
            return []

        strings = set()

        # ASCII strings
        for match in re.finditer(b'[ -~]{' + str(min_length).encode() + b',}', self.hive_data):
            try:
                s = match.group().decode('ascii', errors='ignore')
                if len(s) >= min_length:
                    strings.add(s)
            except:
                pass

        # Unicode strings
        for match in re.finditer(
            b'(?:[\x20-\x7e]\x00){' + str(min_length).encode() + b',}',
            self.hive_data
        ):
            try:
                s = match.group().decode('utf-16-le', errors='ignore')
                if len(s) >= min_length:
                    strings.add(s)
            except:
                pass

        return list(strings)

    @abstractmethod
    def parse(self) -> Dict[str, Any]:
        """Parse hive and extract data"""
        pass
