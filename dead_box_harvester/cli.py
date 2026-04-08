"""Command-line interface"""

import sys
import argparse
from pathlib import Path

from .core.config import HarvesterConfig
from .core.logger import setup_logger
from .harvester import DeadBoxCredentialHarvester


def main():
    """CLI entry point"""
    parser = argparse.ArgumentParser(
        prog="dead-box-harvester",
        description="Windows Dead-Box Credential & PII Harvester",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
USAGE EXAMPLES:
  # Basic extraction (scans current directory as backup)
  %(prog)s /path/to/windows/backup

  # With password for DPAPI decryption
  %(prog)s /mnt/image --password "userpass"

  # Export in hashcat format for password cracking
  %(prog)s /backup --password "pass" --hashcat

  # Selective extraction (credentials only, skip PII)
  %(prog)s /backup --no-pii-scan --output ./results

  # Full forensic analysis with verbose logging
  %(prog)s /backup --password "pass" --hashcat --verbose --log harvest.log

  # Skip specific modules
  %(prog)s /backup --no-browser --no-wifi --no-vault

OUTPUT:
  Results are saved to ./harvester_output/ by default:
  - harvester_report.json  (full report)
  - sam_hashes.csv         (NTLM hashes)
  - hashes_hashcat.txt     (hashcat format)
  - browser_credentials.csv
  - wifi_passwords.csv
  - pii_findings.csv

REQUIREMENTS:
  - Python 3.8+
  - Windows filesystem backup (mounted or extracted)
  - Optional: user password for DPAPI decryption
        """
    )

    parser.add_argument("backup_path", help="Path to Windows backup/image (required)")
    parser.add_argument("--password", help="User password for DPAPI master key derivation")
    parser.add_argument("--output", "-o", default="./harvester_output",
                       help="Output directory (default: ./harvester_output)")
    parser.add_argument("--hashcat", action="store_true",
                       help="Export NTLM hashes in hashcat format ($NT$...)")
    parser.add_argument("--no-pii-scan", action="store_true",
                       help="Disable PII scanning (SSN, API keys, etc.)")
    parser.add_argument("--no-browser", action="store_true",
                       help="Disable browser credential extraction (Chrome, Firefox, Edge)")
    parser.add_argument("--no-wifi", action="store_true",
                       help="Disable WiFi password extraction")
    parser.add_argument("--no-vault", action="store_true",
                       help="Disable Credential Manager extraction")
    parser.add_argument("--verbose", "-v", action="store_true",
                       help="Enable verbose/debug output")
    parser.add_argument("--log", metavar="FILE",
                       help="Write logs to specified file")
    parser.add_argument("--workers", type=int, default=4,
                       help="Number of worker threads (default: 4)")

    args = parser.parse_args()

    # Validate backup path
    backup_path = Path(args.backup_path)
    if not backup_path.exists():
        print(f"Error: Backup path does not exist: {backup_path}")
        sys.exit(1)

    try:
        # Create config
        config = HarvesterConfig(
            backup_path=backup_path,
            user_password=args.password,
            output_dir=Path(args.output),
            enable_pii_scan=not args.no_pii_scan,
            enable_browser_extraction=not args.no_browser,
            enable_wifi_extraction=not args.no_wifi,
            enable_credential_manager=not args.no_vault,
            hashcat_format=args.hashcat,
            verbose=args.verbose,
            max_workers=args.workers,
            log_file=args.log
        )

        # Run harvester
        harvester = DeadBoxCredentialHarvester(config)
        success = harvester.run()

        sys.exit(0 if success else 1)

    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()