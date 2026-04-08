"""Base browser credential extractor"""

import logging
from pathlib import Path
from typing import List, Dict, Any

from ..base import BaseExtractor


logger = logging.getLogger(__name__)


class BaseBrowserExtractor(BaseExtractor):
    """Base class for browser credential extraction"""

    def __init__(self, name: str, dpapi_engine=None):
        super().__init__(name)
        self.dpapi_engine = dpapi_engine

    def extract(self, profile_path: Path) -> List[Dict[str, Any]]:
        """Extract credentials from browser profile"""
        self.logger.info(f"Extracting credentials from {profile_path}")
        return self._extract_credentials(profile_path)

    def _extract_credentials(self, profile_path: Path) -> List[Dict[str, Any]]:
        """Subclass implementation"""
        raise NotImplementedError
