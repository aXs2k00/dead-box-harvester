"""Dead-Box Credential Harvester - Offline Windows credential extraction"""

__version__ = "1.0.0"
__author__ = "Forensic Team"

from .core.config import HarvesterConfig
from .harvester import DeadBoxCredentialHarvester

__all__ = ["HarvesterConfig", "DeadBoxCredentialHarvester"]
