# Windows Dead-Box Credential & PII Harvester

Enterprise-grade offline credential and personally identifiable information (PII) extraction from Windows filesystem backups. Designed for **forensic analysis only** on images where no live system is available.

## ⚠️ IMPORTANT LEGAL NOTICE

**This tool is designed for authorized forensic analysis, incident response, and authorized security testing ONLY.**

- Use only on systems you own or have explicit written authorization to analyze
- Unauthorized access to computer systems is illegal
- This tool should only be used by qualified forensic professionals
- All usage should be documented and comply with applicable laws

## Features

### ✅ Implemented (Offline-Capable)

| Capability | Status | Notes |
|-----------|--------|-------|
| **SAM Hash Extraction** | ✅ Ready | NTLM hashes, hashcat format |
| **LSA Secrets** | ✅ Ready | Service accounts, domain cache |
| **DPAPI Master Key Derivation** | ✅ Ready | From user password + SID |
| **DPAPI Blob Decryption** | ✅ Ready | Credentials, WiFi, Vault |
| **Chrome/Edge Credentials** | ✅ Ready | Pre-v127 (legacy DPAPI) |
| **Firefox Credentials** | ✅ Ready | NSS-encrypted, password-required |
| **WiFi Passwords** | ✅ Ready | From Wlansvc XML profiles |
| **Credential Manager Vault** | ✅ Ready | Generic & web credentials |
| **PII Scanning** | ✅ Ready | SSN, credit cards, emails, API keys |
| **Multi-format Export** | ✅ Ready | JSON, CSV, Hashcat format |

### ⚠️ Limitations

| Capability | Status | Reason |
|-----------|--------|--------|
| Chrome 127+ (2024) | ❌ Not Possible | App-Bound Encryption requires live system |
| Kerberos Tickets | ❌ Not Possible | Stored in memory only |
| LSASS Credentials | ❌ Not Possible | Requires live process memory |
| Master Password (Firefox) | ⚠️ Partial | Requires password input |
| AD Domain Backup Key | ⚠️ Partial | Only available with DPAPI-NG |

## Installation

### Requirements
- Python 3.8+
- Access to filesystem backup/image
- User password (for DPAPI decryption, optional)

### Setup

```bash
# Clone repository
git clone https://github.com/your-repo/dead-box-harvester.git
cd dead-box-harvester

# Install dependencies
pip install -r requirements.txt

# Verify installation
python -m dead_box_harvester --help
```

## Usage

### Basic Extraction

```bash
python -m dead_box_harvester /path/to/backup
```

### With User Password (for DPAPI decryption)

```bash
python -m dead_box_harvester /path/to/backup --password "MyPassword123"
```

### Full Forensic Analysis

```bash
python -m dead_box_harvester /mnt/backup \
  --password "UserPassword" \
  --hashcat \
  --output ./forensic_results \
  --verbose
```

### Selective Extraction

```bash
# Extract only SAM hashes and browser credentials
python -m dead_box_harvester /backup \
  --no-pii-scan \
  --no-wifi \
  --hashcat

# Extract everything
python -m dead_box_harvester /backup \
  --password "pass" \
  --verbose
```

## Output Files

### harvester_report.json
Comprehensive JSON report with all extracted data.

### sam_hashes.csv
NTLM hashes ready for cracking.

### browser_credentials.csv
Extracted browser credentials (encrypted).

### wifi_passwords.csv
WiFi networks and encrypted passwords.

### pii_findings.csv
Discovered personally identifiable information.

### hashes_hashcat.txt
Ready for password cracking.

## Architecture

```
dead-box-harvester/
├── dead_box_harvester/
│   ├── core/           # Configuration, logging, exceptions
│   ├── registry/       # SAM/SECURITY hive parsing
│   ├── dpapi/          # DPAPI decryption engine
│   ├── extractors/     # Credential extractors
│   │   ├── browser/    # Chrome, Firefox, etc.
│   │   ├── wifi/       # WiFi password extraction
│   │   ├── vault/      # Credential Manager
│   │   └── pii/        # PII scanning
│   ├── output/         # Export formatters
│   ├── harvester.py    # Main orchestrator
│   └── cli.py          # Command-line interface
```

## Module Structure

- **Core**: Configuration management, logging setup, custom exceptions
- **Registry**: Native hive parsing for SAM (hashes) and SECURITY (LSA secrets)
- **DPAPI**: Master key derivation and blob decryption
- **Extractors**: Modular credential extraction
  - Browser: Chrome/Edge/Brave (SQLite), Firefox (NSS)
  - WiFi: Wlansvc XML profile parsing
  - Vault: Credential Manager enumeration
  - PII: Content scanning with regex patterns
- **Output**: JSON, CSV, Hashcat format exporters

## Technical Details

### SAM Hash Format
- **NTLM (NTHash):** MD4(password)
- **Hashcat Mode:** 1000 (NTLM)
- **Cracking:** `hashcat -m 1000 hashes.txt wordlist.txt`

### DPAPI Architecture
- Master Key: SHA1(password + SID) → AES-256 key
- Blob Structure: Version | Provider GUID | Master Key GUID | Flags | HMAC | IV | Encrypted Data
- Encryption: AES-256-GCM (Authenticated Encryption)

### Browser Credential Storage
- **Chrome/Edge:** SQLite + DPAPI (legacy) or App-Bound (modern)
- **Firefox:** SQLite + NSS 3DES/AES with master password option
- **All:** Timestamp tracking, usage counts available

### WiFi Password Storage
- **Location:** `ProgramData\Microsoft\Wlansvc\Profiles\Interfaces\{GUID}\*.xml`
- **Format:** XML with encrypted `<keyMaterial>` element
- **Encryption:** DPAPI (same as Credential Manager)

## License

Educational & Authorized Forensic Use Only

---

**⚠️ This tool is provided for authorized security professionals and forensic analysts. Unauthorized access to computer systems is illegal. Always verify you have explicit authorization before using this tool.**
# dead-box-harvester
