"""
Macro Virus Detector - Main Scanner
Phần mềm phát hiện Macro Virus sử dụng kỹ thuật VBA Stomping
"""

import os
import sys
import time
import argparse
from pathlib import Path
from typing import List, Dict
from colorama import init, Fore, Back, Style

# Import modules
from modules.stomping_detector import StompingDetector
from logger import DetectorLogger


# Khởi tạo colorama cho Windows
init(autoreset=True)


class MacroVirusScanner:
    def __init__(self, log_level: str = "INFO", sensitivity: str = "medium"):
        """
        Args:
            log_level: Mức độ log (DEBUG, INFO, WARNING, ERROR)
            sensitivity: Độ nhạy phát hiện (low, medium, high)
        """
        # Setup logger
        log_levels = {
            "DEBUG": 10,
            "INFO": 20,
            "WARNING": 30,
            "ERROR": 40
        }
        self.logger = DetectorLogger(log_level=log_levels.get(log_level, 20))
        
        # Khởi tạo detector với sensitivity
        self.stomping_detector = StompingDetector(sensitivity=sensitivity)
        
        # Statistics
        self.stats = {
            'total_files': 0,
            'infected_files': 0,
            'clean_files': 0,
            'errors': 0,
            'scanned_files': []
        }
    
    def find_docm_files(self, directory: str, recursive: bool = True) -> List[str]:
        """ 
        Args:
            directory: Thư mục cần quét
            recursive: Quét đệ quy các thư mục con
        Returns:
            List đường dẫn các file DOCM
        """
        docm_files = []
        
        try:
            if recursive:
                # Quét đệ quy
                for root, dirs, files in os.walk(directory):
                    for file in files:
                        if file.lower().endswith('.docm'):
                            full_path = os.path.join(root, file)
                            docm_files.append(full_path)
                            self.logger.log_file_found(full_path)
            else:
                # Chỉ quét thư mục hiện tại
                for file in os.listdir(directory):
                    if file.lower().endswith('.docm'):
                        full_path = os.path.join(directory, file)
                        if os.path.isfile(full_path):
                            docm_files.append(full_path)
                            self.logger.log_file_found(full_path)
                            
        except Exception as e:
            self.logger.log_error(f"Lỗi khi tìm file DOCM trong {directory}", e)
        
        return docm_files
    
    def scan_file(self, file_path: str) -> Dict:
        """
        Args:
            file_path: Đường dẫn file cần quét
        Returns:
            Dict chứa kết quả quét
        """
        self.logger.log_file_scanning(file_path)
        
        try:
            # Sử dụng stomping detector
            result = self.stomping_detector.analyze_docm(file_path)
            
            # Cập nhật statistics
            self.stats['total_files'] += 1
            
            if result.get('error'):
                self.stats['errors'] += 1
                self.logger.log_error(f"Lỗi khi quét {file_path}: {result['error']}")
                return result
            
            if result['is_stomped']:
                self.stats['infected_files'] += 1
                self.logger.log_detection(
                    file_path,
                    result['confidence'],
                    result['indicators']
                )
                self._display_warning(file_path, result)
            else:
                self.stats['clean_files'] += 1
                self.logger.log_clean_file(file_path)
            
            self.stats['scanned_files'].append({
                'path': file_path,
                'result': result
            })
            
            return result
            
        except Exception as e:
            self.stats['errors'] += 1
            self.logger.log_error(f"Lỗi khi quét file {file_path}", e)
            return {'error': str(e)}
    
    def scan_directory(self, directory: str, recursive: bool = True):
        """
        Args:
            directory: Thư mục cần quét
            recursive: Quét đệ quy
        """
        self.logger.log_scan_start(directory)
        print(f"\n{Fore.CYAN}{'='*80}")
        print(f"{Fore.CYAN}MACRO VIRUS DETECTOR - VBA STOMPING SCANNER")
        print(f"{Fore.CYAN}{'='*80}\n")
        
        start_time = time.time()
        
        # Tìm tất cả file DOCM
        print(f"{Fore.YELLOW}🔍 Đang tìm kiếm file DOCM...")
        docm_files = self.find_docm_files(directory, recursive)
        
        if not docm_files:
            print(f"{Fore.GREEN}✓ Không tìm thấy file DOCM nào trong thư mục.")
            self.logger.log_info("Không tìm thấy file DOCM nào")
            return
        
        print(f"{Fore.GREEN}✓ Tìm thấy {len(docm_files)} file DOCM\n")
        
        # Quét từng file
        for i, file_path in enumerate(docm_files, 1):
            print(f"{Fore.CYAN}[{i}/{len(docm_files)}] {Fore.WHITE}Đang quét: {os.path.basename(file_path)}")
            self.scan_file(file_path)
            print()
        
        # Kết thúc quét
        duration = time.time() - start_time
        self.logger.log_scan_complete(
            self.stats['total_files'],
            self.stats['infected_files'],
            duration
        )
        
        # Hiển thị kết quả
        self._display_summary(duration)
    
    def _display_warning(self, file_path: str, result: Dict):
        """
        Hiển thị cảnh báo khi phát hiện file bị stomping
        """
        print(f"{Fore.RED}{Back.WHITE}{'!'*80}{Style.RESET_ALL}")
        print(f"{Fore.RED}⚠️  CẢNH BÁO: PHÁT HIỆN VBA STOMPING!{Style.RESET_ALL}")
        print(f"{Fore.RED}{Back.WHITE}{'!'*80}{Style.RESET_ALL}\n")
        
        print(f"{Fore.YELLOW}File: {Fore.WHITE}{file_path}")
        print(f"{Fore.YELLOW}Độ tin cậy: {Fore.RED}{result['confidence']:.1f}%{Style.RESET_ALL}")
        
        if result.get('indicators'):
            print(f"\n{Fore.YELLOW}Dấu hiệu phát hiện được:")
            for indicator in result['indicators']:
                print(f"{Fore.RED}  ✗ {indicator}{Style.RESET_ALL}")
        
        if result.get('details'):
            print(f"\n{Fore.YELLOW}Chi tiết:")
            details = result['details']
            if details.get('has_macros'):
                print(f"{Fore.WHITE}  - Có macro: {Fore.GREEN}Có{Style.RESET_ALL}")
                print(f"{Fore.WHITE}  - Số module: {Fore.CYAN}{details.get('module_count', 0)}{Style.RESET_ALL}")
            
            # Hiển thị chi tiết từ pcodedmp analysis
            if 'pcode_detailed' in details:
                pcode_det = details['pcode_detailed']
                print(f"\n{Fore.CYAN}  🔬 PHÂN TÍCH P-CODE CHI TIẾT (pcodedmp):{Style.RESET_ALL}")
                
                if pcode_det.get('method'):
                    print(f"{Fore.WHITE}     Phương pháp: {Fore.CYAN}{pcode_det['method']}{Style.RESET_ALL}")
                
                if 'pct_missing_ids' in pcode_det:
                    print(f"{Fore.WHITE}     Identifiers thiếu: {Fore.RED}{pcode_det['pct_missing_ids']*100:.1f}%{Style.RESET_ALL}")
                
                if 'pct_missing_strings' in pcode_det:
                    print(f"{Fore.WHITE}     Strings thiếu: {Fore.RED}{pcode_det['pct_missing_strings']*100:.1f}%{Style.RESET_ALL}")
                
                if 'pct_missing_comments' in pcode_det:
                    print(f"{Fore.WHITE}     Comments thiếu: {Fore.RED}{pcode_det['pct_missing_comments']*100:.1f}%{Style.RESET_ALL}")
                
                if 'details' in pcode_det and pcode_det['details'].get('avg_missing_rate'):
                    avg = pcode_det['details']['avg_missing_rate']
                    print(f"{Fore.WHITE}     Tỷ lệ thiếu trung bình: {Fore.RED}{avg*100:.1f}%{Style.RESET_ALL}")
        
        print(f"{Fore.RED}{'='*80}{Style.RESET_ALL}\n")
    
    def _display_summary(self, duration: float):
        """
        Hiển thị tổng kết kết quả quét
        """
        print(f"\n{Fore.CYAN}{'='*80}")
        print(f"{Fore.CYAN}KẾT QUẢ QUÉT")
        print(f"{Fore.CYAN}{'='*80}\n")
        
        print(f"{Fore.WHITE}Tổng số file quét: {Fore.CYAN}{self.stats['total_files']}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}File nhiễm virus: {Fore.RED}{self.stats['infected_files']}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}File sạch: {Fore.GREEN}{self.stats['clean_files']}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Lỗi: {Fore.YELLOW}{self.stats['errors']}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Thời gian: {Fore.CYAN}{duration:.2f}s{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}{'='*80}\n")
        
        print(f"{Fore.YELLOW}📄 Log files:")
        print(f"{Fore.WHITE}  - Main log: {self.logger.log_path}")
        print(f"{Fore.WHITE}  - Detection log: {self.logger.detection_log_path}\n")
        
        if self.stats['infected_files'] > 0:
            print(f"{Fore.RED}⚠️  KHUYẾN NGHỊ:")
            print(f"{Fore.YELLOW}  - Không mở các file bị phát hiện")
            print(f"{Fore.YELLOW}  - Cách ly hoặc xóa các file nghi ngờ")
            print(f"{Fore.YELLOW}  - Kiểm tra kỹ nguồn gốc file")
            print(f"{Fore.YELLOW}  - Xem chi tiết trong file log detection\n")


def main():
    """
    Hàm main
    """
    parser = argparse.ArgumentParser(
        description='Macro Virus Detector - VBA Stomping',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ví dụ sử dụng:
  %(prog)s                          # Quét thư mục hiện tại (đệ quy)
  %(prog)s -d C:\\Documents         # Quét thư mục cụ thể
  %(prog)s -d . --no-recursive      # Chỉ quét thư mục hiện tại (không đệ quy)
  %(prog)s -d . --log-level DEBUG   # Quét với log level DEBUG
        """
    )
    
    parser.add_argument(
        '-d', '--directory',
        type=str,
        default='.',
        help='Thư mục cần quét (mặc định: thư mục hiện tại)'
    )
    
    parser.add_argument(
        '--no-recursive',
        action='store_true',
        help='Không quét đệ quy các thư mục con'
    )
    
    parser.add_argument(
        '--sensitivity',
        type=str,
        choices=['low', 'medium', 'high'],
        default='medium',
        help='Độ nhạy phát hiện: low (50%% thiếu), medium (30%% thiếu), high (10%% thiếu). Mặc định: medium'
    )
    
    parser.add_argument(
        '--log-level',
        type=str,
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default='INFO',
        help='Mức độ log (mặc định: INFO)'
    )
    
    args = parser.parse_args()
    
    # Chuyển đường dẫn thành absolute path
    directory = os.path.abspath(args.directory)
    
    if not os.path.exists(directory):
        print(f"{Fore.RED}❌ Lỗi: Thư mục không tồn tại: {directory}{Style.RESET_ALL}")
        sys.exit(1)
    
    if not os.path.isdir(directory):
        print(f"{Fore.RED}❌ Lỗi: Đường dẫn không phải là thư mục: {directory}{Style.RESET_ALL}")
        sys.exit(1)
    
    # Tạo scanner và bắt đầu quét
    scanner = MacroVirusScanner(
        log_level=args.log_level,
        sensitivity=args.sensitivity
    )
    
    # Hiển thị thông tin sensitivity
    if args.sensitivity != 'medium':
        print(f"{Fore.CYAN}ℹ️  Độ nhạy: {args.sensitivity.upper()}{Style.RESET_ALL}")
    
    try:
        scanner.scan_directory(
            directory,
            recursive=not args.no_recursive
        )
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}⚠️  Quét bị hủy bởi người dùng{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}❌ Lỗi nghiêm trọng: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)


if __name__ == '__main__':
    main()
