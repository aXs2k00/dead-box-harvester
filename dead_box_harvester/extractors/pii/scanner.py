"""PII scanner"""

import logging
import re
from pathlib import Path
from typing import List, Dict, Any, Optional

from .patterns import PIIPatterns
from ..base import BaseExtractor


logger = logging.getLogger(__name__)


class PIIScanner(BaseExtractor):
    """Scan for Personally Identifiable Information"""

    def __init__(self, config: PIIPatterns = None):
        super().__init__("PII Scanner")
        self.config = config or PIIPatterns()
        self.compiled_patterns = {
            name: re.compile(pattern, re.IGNORECASE)
            for name, pattern in self.config.PATTERNS.items()
        }

    def extract(self, directory: Path) -> List[Dict[str, Any]]:
        """Scan directory for PII"""
        return self.scan_directory(directory)

    def scan_directory(self, directory: Path, 
                      extensions: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Scan directory for PII"""
        if extensions is None:
            extensions = ['.txt', '.pdf', '.docx', '.xlsx', '.json', '.xml', '.log', '.conf', '.ini']

        findings = []

        try:
            for file_path in directory.rglob('*'):
                if file_path.is_file() and any(file_path.suffix.lower() == ext for ext in extensions):
                    file_findings = self.scan_file(file_path)
                    findings.extend(file_findings)
        except Exception as e:
            self.logger.warning(f"Error scanning directory {directory}: {e}")

        self.log_extraction(len(findings), "PII instances")
        return findings

    def scan_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """Scan individual file for PII"""
        findings = []

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            self.logger.debug(f"Cannot read file {file_path}: {e}")
            return findings

        for pattern_name, pattern in self.compiled_patterns.items():
            for match in pattern.finditer(content):
                findings.append({
                    "pii_type": pattern_name,
                    "file": str(file_path),
                    "value": match.group()[:100],
                    "confidence": self.config.CONFIDENCE_SCORES.get(pattern_name, 0.70)
                })

        return findings
