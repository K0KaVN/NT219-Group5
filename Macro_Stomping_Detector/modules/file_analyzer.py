"""
File Analyzer - Reusable file analysis functions
Provides common functions for extracting and analyzing Office documents
"""
import sys
import logging
import subprocess
from typing import Optional

try:
    from oletools.olevba import VBA_Parser
except ImportError:
    print("Error: Missing oletools dependency")
    sys.exit(1)

class FileAnalyzer:
    """Reusable file analysis utilities"""
    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)
    
    def extract_vba_with_check(self, file_path: str) -> tuple[bool, str]:
        """
        Extract VBA source code and check if file contains macros (combined operation)
        Returns: (has_macros, vba_source_code)
        """
        try:
            self.logger.debug(f"Extracting VBA from {file_path}")
            vba_parser = VBA_Parser(file_path)
            has_macro = vba_parser.detect_vba_macros()
            
            vba_code = []
            if has_macro:
                for (filename, stream_path, vba_filename, vba_code_text) in vba_parser.extract_macros():
                    if vba_code_text:
                        vba_code.append(vba_code_text)
            
            vba_parser.close()
            return (has_macro, '\n'.join(vba_code))
        except Exception as e:
            error_msg = str(e)
            if "not a supported file type" in error_msg or "Failed to open file" in error_msg:
                raise ValueError(f"Unsupported file type: {error_msg}")
            self.logger.error(f"Error extracting VBA: {e}")
            return (False, "")
    def extract_pcode(self, file_path: str) -> str:
        """
        Extract and decompile P-code from Office document
        """
        try:
            self.logger.debug(f"Extracting P-code from {file_path}")
            cmd = ["pcodedmp", "-d", file_path]
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    encoding='utf-8',
                    errors='ignore',
                    timeout=30
                )
                if result.returncode == 0:
                    return result.stdout
                return self._extract_pcode_api(file_path)
            except FileNotFoundError:
                return self._extract_pcode_api(file_path)
        except Exception as e:
            self.logger.error(f"Error extracting P-code: {e}")
            return ""
    def _extract_pcode_api(self, file_path: str) -> str:
        """Fallback: Extract P-code using pcodedmp Python API"""
        try:
            from pcodedmp.pcodedmp import processFile
            import io
            old_stdout = sys.stdout
            sys.stdout = pcode_output = io.StringIO()
            try:
                processFile(file_path, disasmOnly=False, verbose=False)
            finally:
                sys.stdout = old_stdout
            return pcode_output.getvalue()
        except Exception as e:
            self.logger.error(f"Error using pcodedmp API: {e}")
            return ""

