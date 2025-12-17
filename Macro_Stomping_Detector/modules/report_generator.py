"""
Report Generator Module
Generates detailed reports for VBA Stomping detection results
"""
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List

class ReportGenerator:
    """Generates detection reports in various formats"""
    def __init__(self, output_dir: Path):
        self.output_dir = Path(output_dir)
        self.suspicious_dir = self.output_dir / "suspicious"
        self.summaries_dir = self.output_dir / "summaries"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.suspicious_dir.mkdir(parents=True, exist_ok=True)
        self.summaries_dir.mkdir(parents=True, exist_ok=True)
    def generate_detailed_report(self, result: Dict):
        """Generate detailed report for suspicious file"""
        file_name = result['file_name']
        base_name = os.path.splitext(file_name)[0]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = self.suspicious_dir / f"{base_name}_report_{timestamp}.txt"
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(self._format_detailed_report(result))
    def generate_summary_report(self, results: List[Dict]):
        """Generate combined summary and log report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        summary_file = self.summaries_dir / f"scan_summary_{timestamp}.txt"
        with open(summary_file, 'w', encoding='utf-8') as f:
            f.write(self._format_summary_report(results))
    def _format_detailed_report(self, result: Dict) -> str:
        """Format detailed report for a single file"""
        report_lines = []
        # Header
        report_lines.append("=" * 80)
        report_lines.append("MACRO STOMPING DETECTION REPORT")
        report_lines.append("=" * 80)
        report_lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append("")
        # File information
        report_lines.append("FILE INFORMATION")
        report_lines.append("-" * 80)
        report_lines.append(f"File: {result['file_name']}")
        report_lines.append(f"Path: {result['file_path']}")
        report_lines.append(f"Has Macros: {'Yes' if result['has_macros'] else 'No'}")
        report_lines.append("")
        # Detection results
        if result.get('error'):
            report_lines.append("ERROR")
            report_lines.append("-" * 80)
            report_lines.append(f"Analysis Error: {result['error']}")
            report_lines.append("")
        elif not result['has_macros']:
            report_lines.append("STATUS")
            report_lines.append("-" * 80)
            report_lines.append("Status: NO MACROS DETECTED")
            report_lines.append("")
        else:
            analysis = result.get('analysis')
            if analysis:
                # Status
                report_lines.append("DETECTION STATUS")
                report_lines.append("-" * 80)
                status = "SUSPICIOUS" if result.get('is_suspicious') else "CLEAN"
                report_lines.append(f"Status: {status}")
                report_lines.append(f"Threat Level: {analysis['threat_level']}")
                report_lines.append(f"Confidence Score: {analysis['confidence']}%")
                report_lines.append("")
                # Indicators
                report_lines.append("DETECTION INDICATORS")
                report_lines.append("-" * 80)
                for indicator in analysis['indicators']:
                    report_lines.append(f"• {indicator}")
                report_lines.append("")
                # Behavioral Analysis
                if analysis.get('behavioral_analysis'):
                    behavioral = analysis['behavioral_analysis']
                    if behavioral['high_risk'] or behavioral['medium_risk'] or behavioral['network']:
                        report_lines.append("BEHAVIORAL ANALYSIS (MITRE ATT&CK)")
                        report_lines.append("-" * 80)
                        if behavioral['high_risk']:
                            report_lines.append(f"High-Risk APIs (Hidden): {', '.join(behavioral['high_risk'])}")
                        if behavioral['medium_risk']:
                            report_lines.append(f"Medium-Risk APIs (Hidden): {', '.join(behavioral['medium_risk'])}")
                        if behavioral['network']:
                            report_lines.append(f"Network Indicators (Hidden): {', '.join(behavioral['network'])}")
                        report_lines.append(f"Behavioral Risk Score: {behavioral['risk_score']}/100")
                        report_lines.append("")
                # Mismatch rates
                report_lines.append("PATTERN MISMATCH ANALYSIS")
                report_lines.append("-" * 80)
                mismatch = analysis['mismatch_rates']
                report_lines.append(f"Identifier Mismatch: {mismatch['identifiers']}%")
                report_lines.append(f"String Mismatch: {mismatch['strings']}%")
                report_lines.append(f"Comment Mismatch: {mismatch['comments']}%")
                report_lines.append("")
                # Pattern counts
                report_lines.append("PATTERN STATISTICS")
                report_lines.append("-" * 80)
                pcode_pat = analysis['pcode_patterns']
                vba_pat = analysis['vba_patterns']
                report_lines.append("P-Code Patterns:")
                report_lines.append(f"  - Identifiers: {pcode_pat['identifier_count']}")
                report_lines.append(f"  - Strings: {pcode_pat['string_count']}")
                report_lines.append(f"  - Comments: {pcode_pat['comment_count']}")
                report_lines.append("")
                report_lines.append("VBA Source Patterns:")
                report_lines.append(f"  - Identifiers: {vba_pat['identifier_count']}")
                report_lines.append(f"  - Strings: {vba_pat['string_count']}")
                report_lines.append(f"  - Comments: {vba_pat['comment_count']}")
                report_lines.append("")
                # Unique patterns in P-code
                unique_pcode = analysis['unique_to_pcode']
                if unique_pcode['identifiers'] or unique_pcode['strings']:
                    report_lines.append("UNIQUE PATTERNS IN P-CODE (Not in VBA Source)")
                    report_lines.append("-" * 80)
                    if unique_pcode['identifiers']:
                        report_lines.append("Unique Identifiers (first 20):")
                        for identifier in unique_pcode['identifiers'][:20]:
                            report_lines.append(f"  • {identifier}")
                        report_lines.append("")
                    if unique_pcode['strings']:
                        report_lines.append("Unique Strings (first 20):")
                        for string in unique_pcode['strings'][:20]:
                            report_lines.append(f"  • {string}")
                        report_lines.append("")
                # Recommendation
                report_lines.append("RECOMMENDATION")
                report_lines.append("-" * 80)
                behavioral = analysis.get('behavioral_analysis', {})
                has_high_risk = len(behavioral.get('high_risk', [])) > 0
                if analysis['confidence'] >= 60 or has_high_risk:
                    report_lines.append("[!] QUARANTINE IMMEDIATELY")
                    report_lines.append("This file shows strong indicators of VBA Stomping or hidden malicious code.")
                    report_lines.append("Do not open in production environment.")
                    if has_high_risk:
                        report_lines.append(f"Critical APIs detected: {', '.join(behavioral['high_risk'])}")
                elif analysis['confidence'] >= 30:
                    report_lines.append("[!] INVESTIGATE FURTHER")
                    report_lines.append("This file shows suspicious characteristics.")
                    report_lines.append("Manual analysis recommended in isolated environment.")
                else:
                    report_lines.append("[+] Low risk detected")
                    report_lines.append("File appears to have legitimate macros with no VBA Stomping indicators.")
                report_lines.append("")
        report_lines.append("=" * 80)
        report_lines.append("END OF REPORT")
        report_lines.append("=" * 80)
        return '\n'.join(report_lines)
    def _format_summary_report(self, results: List[Dict]) -> str:
        """Format summary report for all scanned files"""
        report_lines = []
        # Header
        report_lines.append("="  * 80)
        report_lines.append("MACRO STOMPING DETECTION - SCAN SUMMARY")
        report_lines.append("=" * 80)
        report_lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append("")
        # Statistics
        total_files = len(results)
        files_with_macros = sum(1 for r in results if r['has_macros'])
        suspicious_files = sum(1 for r in results if r.get('is_suspicious'))
        clean_files = total_files - suspicious_files
        report_lines.append("SCAN STATISTICS")
        report_lines.append("-" * 80)
        report_lines.append(f"Total Files Scanned: {total_files}")
        report_lines.append(f"Files with Macros: {files_with_macros}")
        report_lines.append(f"Suspicious: {suspicious_files}")
        report_lines.append(f"Clean: {clean_files}")
        report_lines.append("")
        # Suspicious files details
        if suspicious_files > 0:
            report_lines.append("SUSPICIOUS FILES")
            report_lines.append("-" * 80)
            for result in results:
                if result.get('is_suspicious'):
                    confidence = result.get('confidence', 0)
                    threat_level = result.get('analysis', {}).get('threat_level', 'UNKNOWN')
                    report_lines.append(f"\nFile: {result['file_name']}")
                    report_lines.append(f"  Path: {result['file_path']}")
                    report_lines.append(f"  Threat Level: {threat_level}")
                    report_lines.append(f"  Confidence: {confidence}%")
                    if result.get('analysis'):
                        report_lines.append("  Indicators:")
                        for indicator in result['analysis']['indicators'][:5]:
                            report_lines.append(f"    • {indicator}")
            report_lines.append("")
        # Clean files summary
        if clean_files > 0:
            report_lines.append("CLEAN FILES")
            report_lines.append("-" * 80)
            for result in results:
                if not result.get('is_suspicious') and result['has_macros']:
                    confidence = result.get('confidence', 0)
                    report_lines.append(f"• {result['file_name']} (Confidence: {confidence}%)")
            report_lines.append("")
        # Files without macros
        files_no_macros = [r for r in results if not r['has_macros']]
        if files_no_macros:
            report_lines.append("FILES WITHOUT MACROS")
            report_lines.append("-" * 80)
            for result in files_no_macros:
                report_lines.append(f"• {result['file_name']}")
            report_lines.append("")
        # Errors
        files_with_errors = [r for r in results if r.get('error')]
        if files_with_errors:
            report_lines.append("FILES WITH ERRORS")
            report_lines.append("-" * 80)
            for result in files_with_errors:
                report_lines.append(f"• {result['file_name']}: {result['error']}")
            report_lines.append("")
        report_lines.append("=" * 80)
        report_lines.append("END OF SUMMARY")
        report_lines.append("=" * 80)
        return '\n'.join(report_lines)
