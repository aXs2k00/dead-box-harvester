"""WiFi password extractor"""

import logging
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Dict, Any, Optional

from ..base import BaseExtractor


logger = logging.getLogger(__name__)


class WiFiPasswordExtractor(BaseExtractor):
    """Extract WiFi passwords from Wlansvc profiles"""

    # Common WiFi profile locations on Windows
    PROFILE_PATHS = [
        "ProgramData/Microsoft/Wlansvc/Profiles/Interfaces",
        "Windows/System32/wlan/profiles",
    ]

    def __init__(self, dpapi_engine=None):
        super().__init__("WiFi Extractor")
        self.dpapi_engine = dpapi_engine

    def extract(self, backup_path: Path) -> List[Dict[str, Any]]:
        """Extract WiFi profiles and encrypted passwords"""
        return self._extract_wifi_passwords(backup_path)

    def _extract_wifi_passwords(self, backup_path: Path) -> List[Dict[str, Any]]:
        """Extract WiFi profiles from all known locations"""
        wifi_passwords = []

        # Search in all profile paths
        for profile_rel_path in self.PROFILE_PATHS:
            wlan_profiles = backup_path / profile_rel_path
            
            if not wlan_profiles.exists():
                self.logger.debug(f"WiFi profiles directory not found: {wlan_profiles}")
                continue

            try:
                if wlan_profiles.is_file():
                    # Single profile file (older format)
                    profile = self._parse_wifi_profile(wlan_profiles)
                    if profile:
                        wifi_passwords.append(profile)
                else:
                    # Directory structure
                    for interface_dir in wlan_profiles.iterdir():
                        if interface_dir.is_dir():
                            for profile_file in interface_dir.iterdir():
                                if profile_file.suffix.lower() == '.xml':
                                    wifi_profile = self._parse_wifi_profile(profile_file)
                                    if wifi_profile:
                                        wifi_passwords.append(wifi_profile)
            except Exception as e:
                self.logger.warning(f"Error scanning WiFi profiles: {e}")

        self._decrypt_wifi_passwords(wifi_passwords)
        self.log_extraction(len(wifi_passwords), "WiFi profiles")
        return wifi_passwords

    def _parse_wifi_profile(self, profile_file: Path) -> Optional[Dict[str, Any]]:
        """Parse WiFi profile XML file"""
        try:
            # Handle namespaces in Windows WiFi profiles
            with open(profile_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Strip namespace for easier parsing
            content = content.replace('xmlns="http://www.microsoft.com/networking/WLAN/profile/v1"', '')
            
            tree = ET.ElementTree(ET.fromstring(content))
            root = tree.getroot()

            # Extract SSID
            ssid_elem = root.find(".//name")
            ssid = ssid_elem.text if ssid_elem is not None else "Unknown"

            # Extract authentication
            auth_elem = root.find(".//authentication")
            authentication = auth_elem.text if auth_elem is not None else "Unknown"

            # Extract cipher (encryption type)
            cipher_elem = root.find(".//cipher")
            cipher = cipher_elem.text if cipher_elem is not None else "Unknown"

            # Extract key material (encrypted password)
            key_elem = root.find(".//keyMaterial")
            encrypted_key = key_elem.text if key_elem is not None else None

            # Check for MS-MAP element (some profiles use this)
            if not encrypted_key:
                ms_key = root.find(".//MSTA/keyMaterial")
                if ms_key is not None:
                    encrypted_key = ms_key.text

            profile = {
                "type": "wifi",
                "ssid": ssid,
                "authentication": authentication,
                "encryption": cipher,
                "key_material": encrypted_key,
                "key_encrypted": bool(encrypted_key),
                "source_file": str(profile_file),
            }

            # Add MAC if present
            mac_elem = root.find(".//BSSID")
            if mac_elem is not None:
                profile["bssid"] = mac_elem.text

            return profile
            
        except Exception as e:
            self.logger.debug(f"Error parsing WiFi profile {profile_file}: {e}")
            return None

    def _decrypt_wifi_passwords(self, profiles: List[Dict[str, Any]]) -> None:
        """Attempt to decrypt WiFi keys using DPAPI engine"""
        if not self.dpapi_engine or not self.dpapi_engine.is_available():
            for profile in profiles:
                if profile.get("key_encrypted"):
                    profile["decryption_status"] = "requires_password"
                    profile["password"] = None
            return

        for profile in profiles:
            if not profile.get("key_material"):
                profile["decryption_status"] = "no_key_material"
                profile["password"] = None
                continue

            decrypted = self.dpapi_engine.decrypt_wifi_key(profile["key_material"])
            if decrypted:
                profile["password"] = decrypted
                profile["decryption_status"] = "decrypted"
            else:
                profile["decryption_status"] = "decryption_failed"
                profile["password"] = None