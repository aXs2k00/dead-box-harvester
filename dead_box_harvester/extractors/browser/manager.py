"""Browser profile manager"""

import logging
from pathlib import Path
from typing import List, Dict, Any

from .chrome import ChromeCredentialExtractor
from .firefox import FirefoxCredentialExtractor


logger = logging.getLogger(__name__)


class BrowserProfileManager:
    """Manage credential extraction across all browsers"""

    def __init__(self, dpapi_engine=None):
        self.dpapi_engine = dpapi_engine
        self.extractors = {
            "chrome": ChromeCredentialExtractor(dpapi_engine),
            "firefox": FirefoxCredentialExtractor(dpapi_engine),
        }
        logger.info("Browser Profile Manager initialized")

    def find_browser_profiles(self, user_profile: Path) -> Dict[str, List[Path]]:
        """Find all browser profiles in user directory"""
        profiles = {
            "chrome": [],
            "firefox": [],
        }

        # Chrome/Edge/Brave paths
        browser_paths = [
            user_profile / "AppData" / "Local" / "Google" / "Chrome" / "User Data",
            user_profile / "AppData" / "Local" / "Microsoft" / "Edge" / "User Data",
            user_profile / "AppData" / "Local" / "BraveSoftware" / "Brave-Browser" / "User Data",
        ]

        for browser_path in browser_paths:
            if browser_path.exists():
                try:
                    for profile_dir in browser_path.iterdir():
                        if (profile_dir / "Login Data").exists():
                            profiles["chrome"].append(profile_dir)
                except Exception as e:
                    logger.debug(f"Error scanning {browser_path}: {e}")

        # Firefox paths
        firefox_base = user_profile / "AppData" / "Roaming" / "Mozilla" / "Firefox" / "Profiles"
        if firefox_base.exists():
            try:
                for profile_dir in firefox_base.iterdir():
                    if (profile_dir / "logins.json").exists():
                        profiles["firefox"].append(profile_dir)
            except Exception as e:
                logger.debug(f"Error scanning Firefox: {e}")

        return profiles

    def extract_all(self, user_profile: Path) -> List[Dict[str, Any]]:
        """Extract credentials from all browsers"""
        all_credentials = []

        profiles = self.find_browser_profiles(user_profile)

        for browser_type, profile_paths in profiles.items():
            if browser_type in self.extractors:
                for profile_path in profile_paths:
                    try:
                        creds = self.extractors[browser_type].extract(profile_path)
                        all_credentials.extend(creds)
                    except Exception as e:
                        logger.warning(f"Error extracting from {profile_path}: {e}")

        return all_credentials
