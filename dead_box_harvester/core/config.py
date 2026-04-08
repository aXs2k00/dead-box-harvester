"""Configuration management for dead-box harvester"""

from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class HarvesterConfig:
    """Main configuration for credential harvester"""
    backup_path: Path
    user_password: Optional[str] = None  # Required for DPAPI decryption
    output_dir: Path = Path("./harvester_output")
    enable_pii_scan: bool = True
    enable_browser_extraction: bool = True
    enable_wifi_extraction: bool = True
    enable_credential_manager: bool = True
    hashcat_format: bool = False
    verbose: bool = False
    max_workers: int = 4
    log_file: Optional[str] = None

    def __post_init__(self):
        """Validate and normalize configuration"""
        self.backup_path = Path(self.backup_path).resolve()
        self.output_dir = Path(self.output_dir)

        if not self.backup_path.exists():
            raise ValueError(f"Backup path does not exist: {self.backup_path}")

        self.output_dir.mkdir(parents=True, exist_ok=True)
