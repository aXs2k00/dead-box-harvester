"""Main harvester orchestrator"""

import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, Any

from .core.config import HarvesterConfig
from .core.logger import setup_logger
from .registry.sam_parser import SAMHiveParser
from .registry.security_parser import SECURITYHiveParser
from .dpapi.engine import DPAPIEngine
from .extractors.browser.manager import BrowserProfileManager
from .extractors.wifi.extractor import WiFiPasswordExtractor
from .extractors.vault.extractor import CredentialManagerExtractor
from .extractors.pii.scanner import PIIScanner
from .output.manager import OutputManager


logger = logging.getLogger(__name__)


class DeadBoxCredentialHarvester:
    """Main orchestrator for credential and PII extraction from offline Windows backups"""

    def __init__(self, config: HarvesterConfig):
        self.config = config
        self.logger = setup_logger(__name__, config.verbose, config.log_file)
        self.output_manager = OutputManager(config.output_dir)
        self.dpapi_engine = DPAPIEngine(config.user_password)

        self.results: Dict[str, Any] = {
            "metadata": {
                "scan_time": datetime.now().isoformat(),
                "backup_path": str(config.backup_path),
                "version": "1.0.0",
                "dpapi_status": self.dpapi_engine.get_extraction_status()
            },
            "sam_hashes": [],
            "lsa_secrets": [],
            "browser_credentials": [],
            "wifi_passwords": [],
            "credential_manager": [],
            "pii_findings": [],
            "statistics": {}
        }

    def run(self) -> bool:
        """Execute full harvesting pipeline"""
        self.logger.info(f"Starting dead-box harvesting from: {self.config.backup_path}")

        try:
            # Phase 1: SAM hash extraction
            self._extract_sam_hashes()

            # Phase 2: LSA secrets
            self._extract_lsa_secrets()

            # Phase 3: Browser credentials
            if self.config.enable_browser_extraction:
                self._extract_browser_credentials()

            # Phase 4: WiFi passwords
            if self.config.enable_wifi_extraction:
                self._extract_wifi_passwords()

            # Phase 5: Credential Manager
            if self.config.enable_credential_manager:
                self._extract_credential_manager()

            # Phase 6: PII scanning
            if self.config.enable_pii_scan:
                self._scan_pii()

            # Generate statistics and export
            self._generate_statistics()
            self._export_results()

            self.logger.info("Harvesting completed successfully!")
            return True

        except Exception as e:
            self.logger.error(f"Harvesting failed: {e}", exc_info=True)
            return False

    def _extract_sam_hashes(self) -> None:
        """Extract NTLM hashes from SAM hive"""
        self.logger.info("Phase 1: Extracting SAM hashes...")

        sam_path = self.config.backup_path / "Windows" / "System32" / "config" / "SAM"
        if not sam_path.exists():
            self.logger.warning(f"SAM hive not found: {sam_path}")
            return

        parser = SAMHiveParser(sam_path)
        result = parser.parse()
        self.results["sam_hashes"] = result.get("hashes", [])

    def _extract_lsa_secrets(self) -> None:
        """Extract LSA secrets from SECURITY hive"""
        self.logger.info("Phase 2: Extracting LSA secrets...")

        security_path = self.config.backup_path / "Windows" / "System32" / "config" / "SECURITY"
        if not security_path.exists():
            self.logger.warning(f"SECURITY hive not found: {security_path}")
            return

        parser = SECURITYHiveParser(security_path)
        result = parser.parse()
        self.results["lsa_secrets"] = result.get("secrets", [])

    def _extract_browser_credentials(self) -> None:
        """Extract credentials from all browsers"""
        self.logger.info("Phase 3: Extracting browser credentials...")

        users_dir = self.config.backup_path / "Users"
        if not users_dir.exists():
            self.logger.warning(f"Users directory not found: {users_dir}")
            return

        all_credentials = []

        for user_profile in users_dir.iterdir():
            if user_profile.is_dir():
                manager = BrowserProfileManager(self.dpapi_engine)
                creds = manager.extract_all(user_profile)
                all_credentials.extend(creds)

        self.results["browser_credentials"] = all_credentials

    def _extract_wifi_passwords(self) -> None:
        """Extract WiFi passwords from Wlansvc profiles"""
        self.logger.info("Phase 4: Extracting WiFi passwords...")

        extractor = WiFiPasswordExtractor(self.dpapi_engine)
        self.results["wifi_passwords"] = extractor.extract(self.config.backup_path)

    def _extract_credential_manager(self) -> None:
        """Extract Credential Manager vault"""
        self.logger.info("Phase 5: Extracting Credential Manager...")

        users_dir = self.config.backup_path / "Users"
        if not users_dir.exists():
            return

        all_credentials = []

        for user_profile in users_dir.iterdir():
            if user_profile.is_dir():
                extractor = CredentialManagerExtractor(self.dpapi_engine)
                creds = extractor.extract(user_profile)
                all_credentials.extend(creds)

        self.results["credential_manager"] = all_credentials

    def _scan_pii(self) -> None:
        """Scan for PII in user directories"""
        self.logger.info("Phase 6: Scanning for PII...")

        users_dir = self.config.backup_path / "Users"
        if not users_dir.exists():
            self.logger.warning(f"Users directory not found: {users_dir}")
            return

        scanner = PIIScanner()
        all_findings = []

        for user_profile in users_dir.iterdir():
            if user_profile.is_dir():
                for scan_dir in ['Documents', 'Desktop', 'Downloads']:
                    target = user_profile / scan_dir
                    if target.exists():
                        findings = scanner.scan_directory(target)
                        all_findings.extend(findings)

        self.results["pii_findings"] = all_findings

    def _generate_statistics(self) -> None:
        """Generate summary statistics"""
        stats = {
            "sam_hashes_count": len(self.results["sam_hashes"]),
            "lsa_secrets_count": len(self.results["lsa_secrets"]),
            "browser_credentials_count": len(self.results["browser_credentials"]),
            "wifi_profiles_count": len(self.results["wifi_passwords"]),
            "credential_manager_count": len(self.results["credential_manager"]),
            "pii_findings_count": len(self.results["pii_findings"]),
            "total_credentials": (
                len(self.results["sam_hashes"]) +
                len(self.results["browser_credentials"]) +
                len(self.results["credential_manager"])
            )
        }

        self.results["statistics"] = stats
        self.logger.info(f"Statistics: {stats}")

    def _export_results(self) -> None:
        """Export results in multiple formats"""
        self.output_manager.export_all(
            self.results,
            include_hashcat=self.config.hashcat_format
        )
