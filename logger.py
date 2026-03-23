#!/usr/bin/env python3
"""
日志模块 - 支持文件和控制台输出，带轮转功能
"""

import logging
import logging.handlers
import sys
from pathlib import Path
from datetime import datetime


class ColoredFormatter(logging.Formatter):
    """带颜色的日志格式"""
    
    COLORS = {
        'DEBUG': '\033[36m',     # 青色
        'INFO': '\033[32m',      # 绿色
        'WARNING': '\033[33m',   # 黄色
        'ERROR': '\033[31m',     # 红色
        'CRITICAL': '\033[35m',  # 紫色
        'RESET': '\033[0m'
    }
    
    def format(self, record):
        log_color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
        reset = self.COLORS['RESET']
        
        # 时间 [级别] 消息
        msg = f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} {log_color}[{record.levelname}]{reset} {record.getMessage()}"
        return msg


def setup_logger(name: str = "FileServer", 
                 log_file: str = "logs/server.log",
                 level: int = logging.INFO,
                 max_bytes: int = 10*1024*1024,  # 10MB
                 backup_count: int = 5) -> logging.Logger:
    """
    设置日志记录器
    
    Args:
        name: 日志器名称
        log_file: 日志文件路径
        level: 日志级别
        max_bytes: 单个日志文件最大大小
        backup_count: 保留的备份文件数量
    """
    
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # 清除已有处理器
    logger.handlers = []
    
    # 确保日志目录存在
    Path(log_file).parent.mkdir(parents=True, exist_ok=True)
    
    # 文件处理器 - 带轮转
    file_handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding='utf-8'
    )
    file_handler.setLevel(level)
    file_formatter = logging.Formatter(
        '%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)
    
    # 控制台处理器 - 带颜色
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(ColoredFormatter())
    logger.addHandler(console_handler)
    
    return logger


# 全局日志器
server_logger = setup_logger("FileServer")
access_logger = setup_logger("Access", "logs/access.log")
upload_logger = setup_logger("Upload", "logs/upload.log")
auth_logger = setup_logger("Auth", "logs/auth.log")