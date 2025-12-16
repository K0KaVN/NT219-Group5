"""
Logging System for Macro Virus Detector
Hệ thống ghi log cho chương trình phát hiện macro virus
"""

import logging
import os
from datetime import datetime
from typing import Optional


class DetectorLogger:
    """
    Class quản lý logging cho Macro Virus Detector
    """
    
    def __init__(self, log_dir: str = "logs", log_level: int = logging.INFO):
        """
        Khởi tạo logger
        
        Args:
            log_dir: Thư mục chứa file log
            log_level: Mức độ log (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        """
        self.log_dir = log_dir
        self.log_level = log_level
        
        # Tạo thư mục logs nếu chưa có
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        
        # Tạo tên file log theo ngày
        log_filename = f"detector_{datetime.now().strftime('%Y%m%d')}.log"
        self.log_path = os.path.join(log_dir, log_filename)
        
        # Tạo file log cho detection results
        detection_log_filename = f"detections_{datetime.now().strftime('%Y%m%d')}.log"
        self.detection_log_path = os.path.join(log_dir, detection_log_filename)
        
        # Setup logger
        self._setup_logger()
    
    def _setup_logger(self):
        """Thiết lập logger với file và console handlers"""
        # Main logger
        self.logger = logging.getLogger('MacroVirusDetector')
        self.logger.setLevel(self.log_level)
        
        # Xóa handlers cũ nếu có
        self.logger.handlers = []
        
        # Format cho log
        log_format = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # File handler cho main log
        file_handler = logging.FileHandler(self.log_path, encoding='utf-8')
        file_handler.setLevel(self.log_level)
        file_handler.setFormatter(log_format)
        self.logger.addHandler(file_handler)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(self.log_level)
        console_handler.setFormatter(log_format)
        self.logger.addHandler(console_handler)
        
        # Detection logger (riêng cho kết quả phát hiện)
        self.detection_logger = logging.getLogger('DetectionResults')
        self.detection_logger.setLevel(logging.INFO)
        self.detection_logger.handlers = []
        
        detection_format = logging.Formatter(
            '%(asctime)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        detection_handler = logging.FileHandler(self.detection_log_path, encoding='utf-8')
        detection_handler.setLevel(logging.INFO)
        detection_handler.setFormatter(detection_format)
        self.detection_logger.addHandler(detection_handler)
    
    def log_scan_start(self, directory: str):
        """Ghi log khi bắt đầu quét"""
        self.logger.info(f"Bắt đầu quét thư mục: {directory}")
    
    def log_scan_complete(self, total_files: int, infected_files: int, duration: float):
        """Ghi log khi hoàn thành quét"""
        self.logger.info(
            f"Hoàn thành quét - Tổng số file: {total_files}, "
            f"File nhiễm: {infected_files}, Thời gian: {duration:.2f}s"
        )
    
    def log_file_found(self, file_path: str):
        """Ghi log khi tìm thấy file DOCM"""
        self.logger.debug(f"Tìm thấy file DOCM: {file_path}")
    
    def log_file_scanning(self, file_path: str):
        """Ghi log khi đang quét file"""
        self.logger.info(f"Đang quét file: {file_path}")
    
    def log_detection(self, file_path: str, confidence: float, indicators: list):
        """
        Ghi log khi phát hiện file bị stomping
        
        Args:
            file_path: Đường dẫn file
            confidence: Độ tin cậy (%)
            indicators: Danh sách dấu hiệu phát hiện được
        """
        # Log vào main log
        self.logger.warning(
            f"⚠️  PHÁT HIỆN VBA STOMPING - File: {file_path} "
            f"(Độ tin cậy: {confidence:.1f}%)"
        )
        
        for indicator in indicators:
            self.logger.warning(f"  - {indicator}")
        
        # Log vào detection log
        detection_msg = (
            f"FILE: {file_path}\n"
            f"ĐỘ TIN CẬY: {confidence:.1f}%\n"
            f"DẤU HIỆU:\n"
        )
        for indicator in indicators:
            detection_msg += f"  - {indicator}\n"
        detection_msg += "-" * 80
        
        self.detection_logger.warning(detection_msg)
    
    def log_clean_file(self, file_path: str):
        """Ghi log khi file sạch"""
        self.logger.info(f"✓ File sạch: {file_path}")
    
    def log_error(self, message: str, exception: Optional[Exception] = None):
        """Ghi log lỗi"""
        if exception:
            self.logger.error(f"{message}: {str(exception)}", exc_info=True)
        else:
            self.logger.error(message)
    
    def log_warning(self, message: str):
        """Ghi log cảnh báo"""
        self.logger.warning(message)
    
    def log_info(self, message: str):
        """Ghi log thông tin"""
        self.logger.info(message)
    
    def log_debug(self, message: str):
        """Ghi log debug"""
        self.logger.debug(message)
    
    def get_log_summary(self) -> str:
        """
        Lấy summary của log file
        
        Returns:
            String chứa summary
        """
        summary = []
        summary.append("=" * 80)
        summary.append("MACRO VIRUS DETECTOR - LOG SUMMARY")
        summary.append("=" * 80)
        summary.append(f"Main Log: {self.log_path}")
        summary.append(f"Detection Log: {self.detection_log_path}")
        summary.append("=" * 80)
        
        return "\n".join(summary)
