"""Output manager for coordinating all exporters"""

import logging
from pathlib import Path
from typing import List, Dict, Any

from .json_exporter import JSONExporter
from .csv_exporter import CSVExporter
from .hashcat_exporter import HashcatExporter


logger = logging.getLogger(__name__)


class OutputManager:
    """Manage all output exports"""

    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.json_exporter = JSONExporter(output_dir)
        self.csv_exporter = CSVExporter(output_dir)
        self.hashcat_exporter = HashcatExporter(output_dir)
        logger.info(f"Output Manager initialized: {output_dir}")

    def export_json(self, data: Dict[str, Any], filename: str = "report.json") -> Path:
        """Export as JSON"""
        return self.json_exporter.export(data, filename)

    def export_csv(self, data: List[Dict[str, Any]], filename: str = "data.csv") -> Path:
        """Export as CSV"""
        return self.csv_exporter.export(data, filename)

    def export_hashcat(self, hashes: List[Dict[str, str]], filename: str = "hashes.txt") -> Path:
        """Export in hashcat format"""
        return self.hashcat_exporter.export(hashes, filename)

    def export_all(self, results: Dict[str, Any], include_hashcat: bool = False):
        """Export all results"""
        # Main report
        self.export_json(results, "harvester_report.json")

        # Individual exports
        if results.get("sam_hashes"):
            self.export_csv(results["sam_hashes"], "sam_hashes.csv")
            if include_hashcat:
                self.export_hashcat(results["sam_hashes"], "hashes_hashcat.txt")

        if results.get("browser_credentials"):
            self.export_csv(results["browser_credentials"], "browser_credentials.csv")

        if results.get("wifi_passwords"):
            self.export_csv(results["wifi_passwords"], "wifi_passwords.csv")

        if results.get("pii_findings"):
            self.export_csv(results["pii_findings"], "pii_findings.csv")

        logger.info(f"All exports completed to: {self.output_dir}")
