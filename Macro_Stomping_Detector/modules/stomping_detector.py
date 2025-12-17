"""
Stomping Detector - VBA Stomping Detection Module
Detects VBA Stomping technique by comparing P-code with VBA source
"""
import os
import logging
from pathlib import Path
from typing import Dict
from colorama import Fore, Style
from .file_analyzer import FileAnalyzer
from .pattern_analyzer import PatternAnalyzer
from .report_generator import ReportGenerator

class StompingDetector:
    """VBA Stomping detection engine"""
    def __init__(self, output_dir: str = "./reports"):
        self.output_dir = Path(output_dir)
        self.file_analyzer = FileAnalyzer()
        self.pattern_analyzer = PatternAnalyzer()
        self.report_generator = ReportGenerator(self.output_dir)
        self.logger = logging.getLogger(__name__)
    def analyze_file(self, file_path: str) -> Dict:
        """
        Analyze a single file for VBA Stomping
        """
        self.logger.info(f"{Fore.CYAN}Analyzing: {os.path.basename(file_path)}{Style.RESET_ALL}")

        result = {
            'file_path': file_path,
            'file_name': os.path.basename(file_path),
            'has_macros': False,
            'is_suspicious': False,
            'confidence': 0,
            'analysis': None,
            'pcode': '',
            'vba_source': '',
            'error': None
        }
        try:
            try:
                has_macro, vba_source = self.file_analyzer.extract_vba_with_check(file_path)
            except ValueError as ve:
                self.logger.error(f"{Fore.RED}Unsupported file type{Style.RESET_ALL}")
                result['error'] = str(ve)
                return result
            if not has_macro:
                self.logger.info(f"{Fore.YELLOW}No macros found{Style.RESET_ALL}")
                return result
            result['has_macros'] = True
            result['vba_source'] = vba_source
            self.logger.info(f"{Fore.GREEN}[+] Macros detected & VBA source extracted{Style.RESET_ALL}")
            pcode = self.file_analyzer.extract_pcode(file_path)
            if not pcode:
                self.logger.warning("Failed to extract P-code")
                result['error'] = "P-code extraction failed"
                return result
            result['pcode'] = pcode
            self.logger.info(f"{Fore.GREEN}[+] P-code extracted{Style.RESET_ALL}")
            analysis = self.pattern_analyzer.compare_patterns(pcode, vba_source)
            result['analysis'] = analysis
            result['confidence'] = analysis['confidence']
            if result['confidence'] >= 60:
                result['is_suspicious'] = True
                self.logger.warning(f"{Fore.RED}[!] SUSPICIOUS (HIGH) - Confidence: {result['confidence']}%{Style.RESET_ALL}")
                self.report_generator.generate_detailed_report(result)
            elif result['confidence'] >= 30:
                result['is_suspicious'] = True
                self.logger.warning(f"{Fore.YELLOW}[!] SUSPICIOUS (MEDIUM) - Confidence: {result['confidence']}%{Style.RESET_ALL}")
                self.report_generator.generate_detailed_report(result)
            else:
                self.logger.info(f"{Fore.GREEN}[+] CLEAN - Confidence: {result['confidence']}%{Style.RESET_ALL}")
        except Exception as e:
            self.logger.error(f"Error analyzing file: {e}")
            result['error'] = str(e)
        return result
    def scan_files(self, file_list: list) -> list:
        """
        Scan multiple files for VBA Stomping
        """
        results = []
        for file_path in file_list:
            result = self.analyze_file(file_path)
            results.append(result)
        return results
