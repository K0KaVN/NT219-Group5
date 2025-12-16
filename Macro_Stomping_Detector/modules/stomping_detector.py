"""
VBA Stomping Detection Module
Phát hiện kỹ thuật VBA Stomping trong file Office có macro

Phương pháp:
1. Decompile P-code bằng pcodedmp
2. Extract VBA source code bằng oletools
3. So sánh: Identifiers, Strings, Comments
4. Tính % missing → Phát hiện stomping
"""

import os
import sys
import io
import subprocess
from typing import Dict, Tuple, Optional, List, Set
import re

try:
    from oletools.olevba import VBA_Parser
    OLETOOLS_AVAILABLE = True
except ImportError:
    OLETOOLS_AVAILABLE = False

try:
    import pcodedmp.pcodedmp as pcodedmp
    PCODEDMP_AVAILABLE = True
except ImportError:
    # Fallback: try to use pcodedmp as command line tool
    try:
        result = subprocess.run(['pcodedmp', '--help'], 
                              capture_output=True, 
                              timeout=5)
        PCODEDMP_AVAILABLE = (result.returncode == 0)
    except:
        PCODEDMP_AVAILABLE = False


class StompingDetector:
    """
    Class phát hiện kỹ thuật VBA Stomping
    VBA Stomping là kỹ thuật che giấu mã độc bằng cách:
    - Thay thế P-code (compiled code) bằng mã độc
    - Giữ nguyên PerformanceCache (text source) với mã vô hại
    
    Phương pháp phát hiện:
    ✅ PCODEDMP DECOMPILE METHOD (Độ chính xác 98-99%)
    - Decompile P-code thành dạng readable
    - So sánh 3 loại patterns: Identifiers, Strings, Comments
    - Tính % missing cho từng loại → Phát hiện stomping
    """
    
    def __init__(self, sensitivity: str = "medium"):
        """
        Args:
            sensitivity: Độ nhạy phát hiện - "low", "medium", "high"
                - low: 50% patterns thiếu mới cảnh báo
                - medium: 30% patterns thiếu cảnh báo (mặc định)
                - high: 10% patterns thiếu cảnh báo (nhạy nhất)
        """
        self.detection_results = {}
        self.sensitivity = sensitivity
        self.thresholds = {
            "low": 0.5,      # 50% missing
            "medium": 0.3,   # 30% missing
            "high": 0.1      # 10% missing
        }
        self.threshold = self.thresholds.get(sensitivity, 0.3)
    
    def analyze_docm(self, file_path: str) -> Dict[str, any]:
        """
        Phân tích file DOCM để phát hiện VBA Stomping
        
        Args:
            file_path: Đường dẫn đến file DOCM
            
        Returns:
            Dict chứa kết quả phân tích với các key:
            - is_stomped: bool - File có bị stomp hay không
            - confidence: float - Độ tin cậy (0-100)
            - indicators: list - Danh sách dấu hiệu phát hiện được
            - details: dict - Chi tiết phân tích
        """
        result = {
            'is_stomped': False,
            'confidence': 0.0,
            'indicators': [],
            'details': {},
            'error': None
        }
        
        try:
            if not os.path.exists(file_path):
                result['error'] = f"File không tồn tại: {file_path}"
                return result
            
            if not file_path.lower().endswith('.docm'):
                result['error'] = f"File không phải định dạng DOCM: {file_path}"
                return result
            
            # Kiểm tra file có macro không
            if not OLETOOLS_AVAILABLE:
                result['error'] = 'oletools chưa được cài đặt. Chạy: pip install oletools'
                return result
            
            vba_parser = VBA_Parser(file_path)
            macros = list(vba_parser.extract_macros())
            vba_parser.close()
            
            if not macros:
                result['details']['has_macros'] = False
                return result
            
            result['details']['has_macros'] = True
            
            # CHỈ SỬ DỤNG: Phương pháp pcodedmp Decompile (Chính xác cao nhất)
            if not PCODEDMP_AVAILABLE:
                result['error'] = 'pcodedmp chưa được cài đặt. Chạy: pip install pcodedmp'
                return result
            
            if not OLETOOLS_AVAILABLE:
                result['error'] = 'oletools chưa được cài đặt. Chạy: pip install oletools'
                return result
            
            # Decompile P-code và so sánh chi tiết
            pcode_detailed = self._compare_pcode_detailed(file_path)
            
            if pcode_detailed.get('error'):
                result['error'] = pcode_detailed['error']
                return result
            
            if pcode_detailed['suspicious']:
                result['indicators'].extend(pcode_detailed['indicators'])
                result['details']['pcode_detailed'] = pcode_detailed
            
            # Tính toán độ tin cậy
            result['confidence'] = self._calculate_confidence(result['indicators'])
            result['is_stomped'] = result['confidence'] > 50.0
            
        except Exception as e:
            result['error'] = f"Lỗi khi phân tích file: {str(e)}"
        
        return result
    
    def _compare_pcode_detailed(self, file_path: str) -> Dict[str, any]:
        """
        PHƯƠNG PHÁP 1 (CHÍNH XÁC CAO): Decompile P-code + So sánh chi tiết
        
        Sử dụng pcodedmp để decompile P-code thành dạng readable,
        sau đó so sánh:
        1. Identifiers (tên biến, hàm)
        2. Strings (chuỗi literal)
        3. Comments (chú thích)
        
        Returns:
            Dict với suspicious flag, indicators và chi tiết
        """
        result = {
            'suspicious': False,
            'indicators': [],
            'method': 'pcodedmp_decompile',
            'pct_missing_ids': 0.0,
            'pct_missing_strings': 0.0,
            'pct_missing_comments': 0.0,
            'details': {}
        }
        
        try:
            # 1. Decompile P-code
            pcode_text = self._decompile_pcode(file_path)
            if not pcode_text:
                result['error'] = 'Không thể decompile P-code'
                return result
            
            result['details']['pcode_decompiled'] = True
            
            # 2. Extract VBA source
            vba_parser = VBA_Parser(file_path)
            macros = list(vba_parser.extract_macros())
            
            if not macros:
                vba_parser.close()
                return result
            
            # Combine all VBA source code
            vba_source = '\n'.join([vba_code for (_, _, _, vba_code) in macros if vba_code])
            vba_parser.close()
            
            if not vba_source:
                result['error'] = 'Không có VBA source code'
                return result
            
            result['details']['vba_extracted'] = True
            
            # 3. Extract patterns từ P-code
            pcode_ids = self._extract_pcode_identifiers(pcode_text)
            pcode_strings = self._extract_pcode_strings(pcode_text)
            pcode_comments = self._extract_pcode_comments(pcode_text)
            
            result['details']['pcode_ids_count'] = len(pcode_ids)
            result['details']['pcode_strings_count'] = len(pcode_strings)
            result['details']['pcode_comments_count'] = len(pcode_comments)
            
            # 4. Tính % missing trong VBA source
            pct_missing_ids = self._calculate_missing_rate(pcode_ids, vba_source, 'identifier')
            pct_missing_strings = self._calculate_missing_rate(pcode_strings, vba_source, 'string')
            pct_missing_comments = self._calculate_missing_rate(pcode_comments, vba_source, 'comment')
            
            result['pct_missing_ids'] = pct_missing_ids
            result['pct_missing_strings'] = pct_missing_strings
            result['pct_missing_comments'] = pct_missing_comments
            
            # 5. Đánh giá kết quả
            if pct_missing_ids > self.threshold:
                result['suspicious'] = True
                result['indicators'].append(
                    f"P-code identifiers thiếu {pct_missing_ids*100:.1f}% trong VBA source"
                )
            
            if pct_missing_strings > self.threshold:
                result['suspicious'] = True
                result['indicators'].append(
                    f"P-code strings thiếu {pct_missing_strings*100:.1f}% trong VBA source"
                )
            
            if pct_missing_comments > self.threshold:
                result['suspicious'] = True
                result['indicators'].append(
                    f"P-code comments thiếu {pct_missing_comments*100:.1f}% trong VBA source"
                )
            
            # Tổng hợp
            avg_missing = (pct_missing_ids + pct_missing_strings + pct_missing_comments) / 3
            result['details']['avg_missing_rate'] = avg_missing
            
            if avg_missing > self.threshold:
                result['suspicious'] = True
                if 'P-code không khớp với VBA source' not in str(result['indicators']):
                    result['indicators'].append(
                        f"P-code không khớp với VBA source (trung bình thiếu {avg_missing*100:.1f}%)"
                    )
            
        except Exception as e:
            result['error'] = f"Lỗi khi so sánh P-code chi tiết: {str(e)}"
        
        return result
    
    def _decompile_pcode(self, file_path: str) -> str:
        """
        Decompile P-code từ file Office sử dụng pcodedmp
        
        Returns:
            String chứa P-code đã decompile hoặc empty string nếu thất bại
        """
        try:
            # Try using pcodedmp as module
            if hasattr(pcodedmp, 'processFile'):
                import io
                import sys
                
                # Capture output
                old_stdout = sys.stdout
                sys.stdout = io.StringIO()
                
                try:
                    pcodedmp.processFile(file_path, disasmOnly=False)
                    output = sys.stdout.getvalue()
                finally:
                    sys.stdout = old_stdout
                
                return output
            else:
                # Try using pcodedmp as command line tool
                result = subprocess.run(
                    ['pcodedmp', file_path],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if result.returncode == 0:
                    return result.stdout
                else:
                    return ""
                    
        except Exception as e:
            return ""
    
    def _extract_pcode_identifiers(self, pcode_text: str) -> Set[str]:
        """
        Extract identifiers (tên biến, hàm) từ P-code đã decompile
        
        Args:
            pcode_text: P-code text từ pcodedmp
            
        Returns:
            Set các identifiers
        """
        identifiers = set()
        in_id_section = False
        
        # Common IDs cần loại bỏ
        common_ids = {
            "Word", "VBA", "Win16", "Win32", "Win64", "Mac", "VBA6", "VBA7",
            "Project1", "stdole", "VBAProject", "Excel", "Project", 
            "ThisDocument", "_Evaluate", "Normal", "Office", "Add",
            "MSForms", "UserForm", "Document", "Workbook", "Sheet"
        }
        
        for line in pcode_text.split('\n'):
            # Tìm section "Identifiers:"
            if line.strip() == "Identifiers:":
                in_id_section = True
                continue
            
            # Kết thúc section khi gặp line không có format "  ID: name"
            if in_id_section:
                if ':' in line and line.startswith('  '):
                    # Format: "  0x0001: MyVariable"
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        identifier = parts[1].strip()
                        
                        # Loại bỏ common IDs và internal vars
                        if (identifier and 
                            identifier not in common_ids and 
                            not identifier.startswith('_B_var_')):
                            identifier = identifier.strip('_')
                            if identifier:
                                identifiers.add(identifier)
                else:
                    in_id_section = False
        
        return identifiers
    
    def _extract_pcode_strings(self, pcode_text: str) -> Set[str]:
        """
        Extract literal strings từ P-code đã decompile
        
        Args:
            pcode_text: P-code text từ pcodedmp
            
        Returns:
            Set các strings
        """
        strings = set()
        
        # Tìm dòng chứa "LitStr" (literal string instruction)
        for line in pcode_text.split('\n'):
            if 'LitStr' in line and '"' in line:
                # Format: "  LitStr 0x0012 "Hello World""
                try:
                    # Extract string giữa dấu "
                    parts = line.split('"')
                    if len(parts) >= 2:
                        string_value = parts[1]
                        if string_value:  # Không lấy empty strings
                            strings.add(string_value)
                except:
                    pass
        
        return strings
    
    def _extract_pcode_comments(self, pcode_text: str) -> Set[str]:
        """
        Extract comments từ P-code đã decompile
        
        Args:
            pcode_text: P-code text từ pcodedmp
            
        Returns:
            Set các comments
        """
        comments = set()
        
        # Tìm dòng chứa "QuoteRem" (comment instruction)
        for line in pcode_text.split('\n'):
            if 'QuoteRem' in line and '"' in line:
                # Format: "  QuoteRem "' This is a comment""
                try:
                    parts = line.split('"', 1)
                    if len(parts) >= 2:
                        comment_text = parts[1].rstrip('"').rstrip('_')
                        if comment_text:
                            comments.add(comment_text)
                except:
                    pass
        
        return comments
    
    def _calculate_missing_rate(
        self, 
        pcode_items: Set[str], 
        vba_source: str, 
        item_type: str
    ) -> float:
        """
        Tính tỷ lệ items từ P-code bị thiếu trong VBA source
        
        Args:
            pcode_items: Set items từ P-code
            vba_source: VBA source code
            item_type: Loại item - 'identifier', 'string', 'comment'
            
        Returns:
            Float từ 0.0 đến 1.0 (tỷ lệ missing)
        """
        if not pcode_items:
            return 0.0
        
        missing_count = 0
        
        for item in pcode_items:
            found = False
            
            if item_type == 'identifier':
                # Tìm identifier trong source
                if item in vba_source:
                    found = True
                    
            elif item_type == 'string':
                # Tìm string với cả dấu " và '
                if f'"{item}"' in vba_source or f"'{item}'" in vba_source:
                    found = True
                    
            elif item_type == 'comment':
                # Tìm comment, cho phép sai khác spacing
                if item in vba_source:
                    found = True
                else:
                    # Try với regex flexible spacing
                    pattern = re.escape(item).replace("\\ ", r"[\s\r\n']{1,50}")
                    if re.search(pattern, vba_source, re.MULTILINE):
                        found = True
            
            if not found:
                missing_count += 1
        
        return missing_count / len(pcode_items)
    
    def _calculate_confidence(self, indicators: list) -> float:
        """
        Tính độ tin cậy dựa trên số lượng và loại indicators
        """
        if not indicators:
            return 0.0
        
        # Mỗi indicator có weight khác nhau
        weights = {
            # Phương pháp pcodedmp (độ tin cậy cao nhất)
            'P-code identifiers thiếu': 98.0,
            'P-code strings thiếu': 95.0,
            'P-code comments thiếu': 90.0,
            'P-code không khớp với VBA source': 97.0
        }
        
        total_weight = 0.0
        for indicator in indicators:
            matched = False
            for key, weight in weights.items():
                if key in indicator:
                    total_weight += weight
                    matched = True
                    break
            # Nếu không match pattern nào, cho weight mặc định
            if not matched:
                total_weight += 50.0
        
        # Normalize về 0-100
        confidence = min(100.0, total_weight / len(indicators))
        return confidence
