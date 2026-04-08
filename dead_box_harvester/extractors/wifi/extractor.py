"""WiFi password extractor"""

import logging
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Dict, Any, Optional

from ..base import BaseExtractor


logger = logging.getLogger(__name__)


class WiFiPasswordExtractor(BaseExtractor):
    """Extract WiFi passwords from Wlansvc profiles"""

    def __init__(self, dpapi_engine=None):
        super().__init__("WiFi Extractor")
        self.dpapi_engine = dpapi_engine

    def extract(self, backup_path: Path) -> List[Dict[str, Any]]:
        """Extract WiFi profiles and encrypted passwords"""
        return self._extract_wifi_passwords(backup_path)

    def _extract_wifi_passwords(self, backup_path: Path) -> List[Dict[str, Any]]:
        """Extract WiFi profiles"""
        wifi_passwords = []

        wlan_profiles = backup_path / "ProgramData" / "Microsoft" / "Wlansvc" / "Profiles" / "Interfaces"

        if not wlan_profiles.exists():
            self.logger.debug(f"WiFi profiles directory not found: {wlan_profiles}")
            return wifi_passwords

        try:
            for interface_dir in wlan_profiles.iterdir():
                if interface_dir.is_dir():
                    for profile_file in interface_dir.iterdir():
                        if profile_file.suffix == '.xml':
                            wifi_profile = self._parse_wifi_profile(profile_file)
                            if wifi_profile:
                                wifi_passwords.append(wifi_profile)
        except Exception as e:
            self.logger.warning(f"Error extracting WiFi passwords: {e}")

        self.log_extraction(len(wifi_passwords), "WiFi profiles")
        return wifi_passwords

    def _parse_wifi_profile(self, profile_file: Path) -> Optional[Dict[str, Any]]:
        """Parse WiFi profile XML file"""
        try:
            tree = ET.parse(profile_file)
            root = tree.getroot()

            ssid_elem = root.find(".//name")
            ssid = ssid_elem.text if ssid_elem is not None else "Unknown"

            auth_elem = root.find(".//authentication")
            authentication = auth_elem.text if auth_elem is not None else "Unknown"

            key_material_elem = root.find(".//keyMaterial")
            key_material = key_material_elem.text if key_material_elem is not None else None

            return {
                "ssid": ssid,
                "authentication": authentication,
                "encrypted_key": key_material,
                "encryption_type": "DPAPI",
                "source_file": str(profile_file),
                "decryption_required": bool(key_material),
                "decryption_status": "requires_dpapi_decryption"
            }
        except Exception as e:
            self.logger.debug(f"Error parsing WiFi profile {profile_file}: {e}")
            return None
