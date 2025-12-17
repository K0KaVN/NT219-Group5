#!/usr/bin/env python3
"""
Macro Stomping Detector
"""
import sys
import argparse
import logging
from datetime import datetime
from pathlib import Path
from modules.stomping_detector import StompingDetector

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError as e:
    print(f"Error: Missing required dependency - {e}")
    print("Please install: pip install -r requirements.txt")
    sys.exit(1)
class MacroStompingDetector:
    """Main detector orchestrator"""
    def __init__(self, output_dir: str = "./reports"):
        self.output_dir = Path(output_dir)
        self.stomping_detector = StompingDetector(output_dir)
        self.setup_logging()
    def setup_logging(self):
        """Setup logging to logs_summary directory"""
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        if hasattr(console_handler.stream, 'reconfigure'):
            try:
                console_handler.stream.reconfigure(encoding='utf-8')
            except:
                pass
        logging.basicConfig(
            level=logging.INFO,
            handlers=[console_handler]
        )
        self.logger = logging.getLogger(__name__)
    def find_docm_files(self, directory: str, recursive: bool = False):
        """Find all .docm files in directory"""
        self.logger.info(f"Scanning directory: {directory}")
        path = Path(directory)
        if not path.exists():
            self.logger.error(f"Directory not found: {directory}")
            return []
        pattern = "**/*.docm" if recursive else "*.docm"
        docm_files = [str(f) for f in path.glob(pattern)]
        self.logger.info(f"Found {len(docm_files)} .docm file(s)")
        return docm_files
    def scan_directory(self, directory: str, recursive: bool = False):
        """Scan directory and analyze all .docm files"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"MACRO STOMPING DETECTOR")
        print(f"{'='*60}{Style.RESET_ALL}\n")
        docm_files = self.find_docm_files(directory, recursive)
        if not docm_files:
            print(f"{Fore.YELLOW}No .docm files found{Style.RESET_ALL}")
            return
        results = self.stomping_detector.scan_files(docm_files)
        self.stomping_detector.report_generator.generate_summary_report(results)

        suspicious_count = sum(1 for r in results if r.get('is_suspicious'))
        high_suspicious = [r for r in results if r.get('is_suspicious') and r.get('confidence', 0) >= 60]
        medium_suspicious = [r for r in results if r.get('is_suspicious') and 30 <= r.get('confidence', 0) < 60]
        error_count = sum(1 for r in results if r.get('error'))
        clean_count = len(results) - suspicious_count - error_count
        
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"SCAN SUMMARY")
        print(f"{'='*60}{Style.RESET_ALL}")
        print(f"Total files scanned: {len(results)}")
        print(f"Files with macros: {sum(1 for r in results if r['has_macros'])}")
        print(f"{Fore.RED}Suspicious: {suspicious_count}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Clean: {clean_count}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Errors: {error_count}{Style.RESET_ALL}")
        
        if high_suspicious:
            print(f"\n{Fore.RED}Files with HIGH suspicious:{Style.RESET_ALL}")
            for result in high_suspicious:
                print(f"  - {result['file_name']}: {result.get('confidence', 0)}%")
        if medium_suspicious:
            print(f"\n{Fore.YELLOW}Files with MEDIUM suspicious:{Style.RESET_ALL}")
            for result in medium_suspicious:
                print(f"  - {result['file_name']}: {result.get('confidence', 0)}%")
        if error_count > 0:
            print(f"\n{Fore.YELLOW}Files with errors:{Style.RESET_ALL}")
            for result in results:
                if result.get('error'):
                    print(f"  - {result['file_name']}: {result['error'][:60]}...")
        print(f"\nReports saved to: {self.output_dir}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")

def main():
    parser = argparse.ArgumentParser(
        description='Macro Stomping Detector - Detect VBA Stomping in Office documents',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        '-d', '--directory',
        required=True,
        help='Directory containing .docm files to scan'
    )
    parser.add_argument(
        '-r', '--recursive',
        action='store_true',
        help='Scan subdirectories recursively'
    )
    args = parser.parse_args()
    detector = MacroStompingDetector()
    try:
        detector.scan_directory(args.directory, args.recursive)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}Fatal error: {e}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main()
