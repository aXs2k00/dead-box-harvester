"""CSV output exporter"""

import csv
import logging
from pathlib import Path
from typing import List, Dict, Any

from .base import BaseExporter


logger = logging.getLogger(__name__)


class CSVExporter(BaseExporter):
    """Export data as CSV"""

    def export(self, data: List[Dict[str, Any]], filename: str = "data.csv") -> Path:
        """Save data as CSV"""
        if not data:
            self.logger.warning(f"No data to export to {filename}")
            return None

        output_file = self.output_dir / filename

        try:
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=data[0].keys())
                writer.writeheader()
                writer.writerows(data)

            self.logger.info(f"Saved CSV: {output_file}")
            return output_file
        except Exception as e:
            self.logger.error(f"CSV export failed: {e}")
            raise
