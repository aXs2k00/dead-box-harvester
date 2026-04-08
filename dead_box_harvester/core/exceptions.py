"""Custom exceptions for dead-box harvester"""


class HarvesterException(Exception):
    """Base exception for harvester"""
    pass


class RegistryParseException(HarvesterException):
    """Registry parsing failed"""
    pass


class DPAPIException(HarvesterException):
    """DPAPI operations failed"""
    pass


class BrowserExtractionException(HarvesterException):
    """Browser credential extraction failed"""
    pass


class WiFiExtractionException(HarvesterException):
    """WiFi password extraction failed"""
    pass


class VaultExtractionException(HarvesterException):
    """Credential vault extraction failed"""
    pass


class PIIScanException(HarvesterException):
    """PII scanning failed"""
    pass


class ExportException(HarvesterException):
    """Data export failed"""
    pass
