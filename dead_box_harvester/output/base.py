"""Base output exporter"""

import logging
from pathlib import Path
from abc import ABC, abstractmethod
from typing import Any, Dict, List


logger = logging.getLogger(__name__)


class BaseExporter(ABC):
    """Base class for output exporters"""

    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    @abstractmethod
    def export(self, data: Any, filename: str) -> Path:
        """Export data to file"""
        pass
