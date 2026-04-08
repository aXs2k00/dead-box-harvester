"""Base extractor class"""

import logging
from abc import ABC, abstractmethod
from typing import List, Dict, Any


logger = logging.getLogger(__name__)


class BaseExtractor(ABC):
    """Base class for all extractors"""

    def __init__(self, name: str):
        self.name = name
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    @abstractmethod
    def extract(self, *args, **kwargs) -> List[Dict[str, Any]]:
        """Extract credentials/data"""
        pass

    def log_extraction(self, count: int, item_type: str):
        """Log extraction result"""
        self.logger.info(f"Extracted {count} {item_type} from {self.name}")
