#!/usr/bin/env python3
"""
认证模块 - 支持Basic Auth和Session Token
"""

import base64
import secrets
import hashlib
import time
from typing import Optional, Dict, Tuple
from dataclasses import dataclass, field

from config import AUTH_CONFIG
from logger import auth_logger


@dataclass
class Session:
    """用户Session"""
    username: str
    created_at: float = field(default_factory=time.time)
    last_access: float = field(default_factory=time.time)
    token: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    
    def is_valid(self) -> bool:
        """检查Session是否过期"""
        timeout = AUTH_CONFIG.get("session_timeout", 3600)
        return (time.time() - self.last_access) < timeout
    
    def touch(self):
        """更新最后访问时间"""
        self.last_access = time.time()


class AuthManager:
    """认证管理器"""
    
    def __init__(self):
        self.sessions: Dict[str, Session] = {}  # token -> Session
        self._lock = False  # 简单锁，生产环境用threading.Lock
    
    def verify_basic_auth(self, auth_header: str) -> Optional[Tuple[str, str]]:
        """
        验证Basic Auth
        
        Returns:
            (username, role) 或 None
        """
        if not auth_header or not auth_header.startswith('Basic '):
            auth_logger.debug("Invalid auth header format")
            return None
        
        try:
            encoded = auth_header[6:]
            decoded = base64.b64decode(encoded).decode('utf-8')
            username, password = decoded.split(':', 1)
            
            if username in AUTH_CONFIG["users"]:
                if AUTH_CONFIG["users"][username] == password:
                    role = "readonly" if username in AUTH_CONFIG.get("readonly_users", []) else "admin"
                    auth_logger.info(f"Basic auth success: {username} ({role})")
                    return (username, role)
                else:
                    auth_logger.warning(f"Wrong password for user: {username}")
            else:
                auth_logger.warning(f"Unknown user: {username}")
                
        except Exception as e:
            auth_logger.error(f"Auth decode error: {e}")
        
        return None
    
    def create_session(self, username: str) -> str:
        """创建新Session"""
        # 清理过期session
        self._cleanup_sessions()
        
        session = Session(username=username)
        self.sessions[session.token] = session
        auth_logger.info(f"Session created for {username}: {session.token[:8]}...")
        return session.token
    
    def verify_token(self, token: str) -> Optional[Tuple[str, str]]:
        """
        验证Token
        
        Returns:
            (username, role) 或 None
        """
        if not token or token not in self.sessions:
            return None
        
        session = self.sessions[token]
        if not session.is_valid():
            auth_logger.info(f"Session expired: {token[:8]}...")
            del self.sessions[token]
            return None
        
        session.touch()
        role = "readonly" if session.username in AUTH_CONFIG.get("readonly_users", []) else "admin"
        return (session.username, role)
    
    def destroy_session(self, token: str):
        """销毁Session"""
        if token in self.sessions:
            username = self.sessions[token].username
            del self.sessions[token]
            auth_logger.info(f"Session destroyed for {username}")
    
    def _cleanup_sessions(self):
        """清理过期Session"""
        expired = [t for t, s in self.sessions.items() if not s.is_valid()]
        for t in expired:
            del self.sessions[t]
        if expired:
            auth_logger.debug(f"Cleaned up {len(expired)} expired sessions")


# 全局认证实例
auth_manager = AuthManager()