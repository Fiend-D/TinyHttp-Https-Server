#!/usr/bin/env python3
"""
配置文件
"""

import os
from pathlib import Path

# 基础路径
BASE_DIR = Path(__file__).parent.absolute()
UPLOAD_DIR = Path("/home/fiend/Downloads/serverPath/work")
SECURITY_DIR = Path("/home/fiend/Downloads/serverPath/fiend")
STATIC_DIR = BASE_DIR / "static"
LOGS_DIR = BASE_DIR / "logs"

# # 确保目录存在
for d in [UPLOAD_DIR, STATIC_DIR, LOGS_DIR, SECURITY_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# 服务器配置
SERVER_CONFIG = {
    "http_port": 8080,           # HTTP端口（0表示关闭）
    "https_port": 8443,          # HTTPS端口（0表示关闭）
    "host": "0.0.0.0",           # 监听地址
    "directory": [UPLOAD_DIR, SECURITY_DIR],  # 添加这一行！
    "ssl_cert": BASE_DIR / "server.pem",
    "ssl_key": None,             # 如果证书包含key则设为None
    
    "max_upload_size": 1024 * 1024 * 1024,  # 1GB
    "chunk_size": 8192,          # 文件传输块大小
    
    "enable_web": True,          # 启用Web界面
    "enable_api": True,          # 启用API
    "enable_upload": True,       # 允许上传
    "enable_delete": True,       # 允许删除
}

# 认证配置
AUTH_CONFIG = {
    "users": {
        "work": "123",
        "admin":"admin",
        "1234": "1234",          # 测试用户，用户名和密码相同
        "readonly": "read123",    # 只读用户
    },
    "security_users": ["fiend"],  # 这些用户只能访问安全目录
    "readonly_users": ["readonly"],  # 这些用户只有下载权限
    "session_timeout": 3600,      # Session过期时间（秒）
    "token_header": "X-Auth-Token", # API Token头
}

# Web配置
WEB_CONFIG = {
    "title": "File Server",
    "items_per_page": 20,
    "allowed_types": "*",        # 允许的文件类型，*表示全部
    "theme": "light",            # light/dark
}

# 日志配置
LOG_CONFIG = {
    "level": "INFO",
    "access_log": LOGS_DIR / "access.log",
    "max_size": 10 * 1024 * 1024,  # 10MB
    "backup_count": 5,
}