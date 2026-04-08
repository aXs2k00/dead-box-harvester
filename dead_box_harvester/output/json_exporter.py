"""JSON output exporter"""

import json
import logging
from pathlib import Path
from typing import Any

from .base import BaseExporter


logger = logging.getLogger(__name__)


class JSONExporter(BaseExporter):
    """Export data as JSON"""

    def export(self, data: Any, filename: str = "report.json") -> Path:
        """Save data as JSON"""
        output_file = self.output_dir / filename

        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False, default=str)

            self.logger.info(f"Saved JSON: {output_file}")
            return output_file
        except Exception as e:
            self.logger.error(f"JSON export failed: {e}")
            raise
