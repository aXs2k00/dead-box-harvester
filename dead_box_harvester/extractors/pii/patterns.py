"""PII detection patterns"""


class PIIPatterns:
    """Comprehensive PII detection patterns"""

    PATTERNS = {
        "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
        "credit_card": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b",
        "phone_us": r"\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b",
        "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "api_key_generic": r"(?i)(api[_-]?key|apikey|access[_-]?token)[\'\"]?\s*[:=]\s*[\'\"]?([a-zA-Z0-9\-_]{16,})",
        "aws_access_key": r"\bAKIA[0-9A-Z]{16}\b",
        "aws_secret_key": r"(?i)aws[_-]?secret[_-]?access[_-]?key[\'\"]?\s*[:=]\s*[\'\"]?([a-zA-Z0-9/+=]{40})",
        "github_token": r"\bghp_[a-zA-Z0-9]{36}\b",
        "slack_token": r"\bxox[baprs]-[a-zA-Z0-9-]+\b",
        "private_key_rsa": r"-----BEGIN RSA PRIVATE KEY-----",
        "private_key_dsa": r"-----BEGIN DSA PRIVATE KEY-----",
        "private_key_ec": r"-----BEGIN EC PRIVATE KEY-----",
        "private_key_openssh": r"-----BEGIN OPENSSH PRIVATE KEY-----",
        "bitcoin_address": r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b",
        "ethereum_address": r"\b0x[a-fA-F0-9]{40}\b",
        "passport": r"\b[A-Z]{2}[0-9]{7}\b",
        "bank_account": r"\b\d{8,17}\b",
        "ip_address": r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
        "mac_address": r"\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b",
    }

    CONFIDENCE_SCORES = {
        "ssn": 0.95,
        "credit_card": 0.90,
        "phone_us": 0.80,
        "email": 0.85,
        "api_key_generic": 0.75,
        "aws_access_key": 0.99,
        "aws_secret_key": 0.95,
        "github_token": 0.99,
        "slack_token": 0.99,
        "private_key_rsa": 0.99,
        "private_key_dsa": 0.99,
        "private_key_ec": 0.99,
        "private_key_openssh": 0.99,
        "bitcoin_address": 0.90,
        "ethereum_address": 0.90,
        "passport": 0.70,
        "bank_account": 0.60,
        "ip_address": 0.50,
        "mac_address": 0.50,
    }
