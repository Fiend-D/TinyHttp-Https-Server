#!/usr/bin/env python3
"""
API处理器 - 供curl/python等工具调用
支持: 上传(PUT/POST)、下载(GET)、删除(DELETE)、列表(GET /list)
"""

import json
import urllib.parse
import cgi
import os
from pathlib import Path
from typing import Optional, Tuple

from logger import server_logger, access_logger, upload_logger
from config import SERVER_CONFIG, UPLOAD_DIR, AUTH_CONFIG
from auth import auth_manager


class APIHandler:
    """API请求处理器"""
    
    def __init__(self, request_handler):
        self.rh = request_handler  # BaseHTTPRequestHandler实例
        self.username: Optional[str] = None
        self.role: str = "guest"
    
    def _safe_filename(self, filename: str) -> Optional[str]:
        """安全检查文件名，防止目录遍历"""
        if not filename:
            return None
        
        # 规范化路径
        filename = filename.replace('\\', '/')
        filename = os.path.basename(filename)  # 只保留文件名部分
        
        # 禁止 .. 和隐藏文件
        if '..' in filename or filename.startswith('.'):
            return None
        
        # 清理非法字符
        filename = ''.join(c for c in filename if c.isalnum() or c in '._-')
        
        if not filename or filename in ['.', '..']:
            return None
        
        return filename

    def _human_size(self, size: int) -> str:
        """人性化文件大小"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} PB"
    
    def _format_time(self, timestamp: float) -> str:
        """格式化时间"""
        from datetime import datetime
        return datetime.fromtimestamp(timestamp).isoformat()

    def check_auth(self) -> bool:
        """检查认证"""
        # 1. 检查Token (API优先)
        token = self.rh.headers.get(AUTH_CONFIG["token_header"], '')
        if token:
            result = auth_manager.verify_token(token)
            if result:
                self.username, self.role = result
                return True
        
        # 2. 检查Basic Auth
        auth_header = self.rh.headers.get('Authorization', '')
        result = auth_manager.verify_basic_auth(auth_header)
        if result:
            self.username, self.role = result
            # 为API创建session并返回token
            token = auth_manager.create_session(self.username)
            self.rh.send_header(AUTH_CONFIG["token_header"], token)
            return True
        
        return False
    
    def send_auth_required(self):
        """返回401"""
        self.rh.send_response(401)
        self.rh.send_header('WWW-Authenticate', 'Basic realm="FileServer API"')
        self.rh.send_header('Content-type', 'application/json')
        self.rh.end_headers()
        self.rh.wfile.write(json.dumps({
            "error": "Unauthorized",
            "message": "Please provide valid credentials"
        }).encode())
    
    def send_json(self, data: dict, status: int = 200):
        """发送JSON响应"""
        self.rh.send_response(status)
        self.rh.send_header('Content-type', 'application/json')
        self.rh.end_headers()
        self.rh.wfile.write(json.dumps(data, indent=2).encode())
    
    def send_error(self, code: int, message: str):
        """发送错误"""
        self.send_json({"error": message}, code)
    
    def handle(self, method: str):
        """分发请求"""
        if not self.check_auth():
            access_logger.warning(f"Unauthorized {method} request from {self.rh.client_address[0]}")
            self.send_auth_required()
            return
        
        access_logger.info(f"{method} {self.rh.path} by {self.username} ({self.role})")
        
        try:
            if method == 'GET':
                self.do_get()
            elif method == 'PUT':
                self.do_put()
            elif method == 'POST':
                self.do_post()
            elif method == 'DELETE':
                self.do_delete()
            elif method == 'HEAD':
                self.do_head()
            else:
                self.send_error(405, "Method not allowed")
        except Exception as e:
            server_logger.error(f"Error handling {method}: {e}", exc_info=True)
            self.send_error(500, str(e))
    
    def do_get(self):
        """GET - 下载文件或列表"""
        path = urllib.parse.unquote(self.rh.path).lstrip('/')
        
        # 列表接口
        if path == '' or path == 'list':
            self.list_files()
            return
        
        # 下载文件
        self.download_file(path)
    
    def do_put(self):
        """PUT - 上传文件（curl -T）"""
        if self.role == "readonly":
            self.send_error(403, "Read-only user cannot upload")
            return
        
        if not SERVER_CONFIG["enable_upload"]:
            self.send_error(403, "Upload disabled")
            return
        
        # 获取文件名
        filename = urllib.parse.unquote(self.rh.path).lstrip('/') or 'unnamed'
        
        # 获取Content-Length（必须）
        content_length = self.rh.headers.get('Content-Length')
        if content_length is None:
            # 不支持 chunked encoding，返回411 Length Required
            self.send_error(411, "Content-Length required")
            return
        
        try:
            length = int(content_length)
        except ValueError:
            self.send_error(400, "Invalid Content-Length")
            return
        
        if length > SERVER_CONFIG["max_upload_size"]:
            self.send_error(413, f"File too large. Max: {self._human_size(SERVER_CONFIG['max_upload_size'])}")
            return
        
        if length == 0:
            self.send_error(400, "Empty file")
            return
        
        # 先发送100 Continue（如果客户端请求了）
        expect = self.rh.headers.get('Expect', '')
        if '100-continue' in expect.lower():
            self.rh.send_response(100)
            self.rh.end_headers()
            server_logger.debug("Sent 100 Continue")
        
        # 保存上传
        self.save_upload(filename, self.rh.rfile, length)
        
    def do_post(self):
        """POST - 支持 multipart 和原始数据"""
        if self.role == "readonly":
            self.send_error(403, "Read-only user cannot upload")
            return
        
        if not SERVER_CONFIG["enable_upload"]:
            self.send_error(403, "Upload disabled")
            return
        
        content_type = self.rh.headers.get('Content-Type', '')
        content_length = self.rh.headers.get('Content-Length')
        
        server_logger.debug(f"POST path={self.rh.path}, Content-Type={content_type}, Length={content_length}")
        
        if content_length is None:
            self.send_error(411, "Content-Length required")
            return
        
        try:
            length = int(content_length)
        except ValueError:
            self.send_error(400, "Invalid Content-Length")
            return
        
        if length == 0:
            self.send_error(400, "Empty file")
            return
        
        if length > SERVER_CONFIG["max_upload_size"]:
            self.send_error(413, f"File too large, max {self._human_size(SERVER_CONFIG['max_upload_size'])}")
            return
        
        # 处理 Expect: 100-continue
        expect = self.rh.headers.get('Expect', '')
        if '100-continue' in expect.lower():
            self.rh.send_response(100)
            self.rh.end_headers()
            server_logger.debug("Sent 100 Continue")
        
        # 获取文件名 - 优先级：X-File-Name header > URL path > default
        filename = None
        
        # 1. 尝试从 header 获取
        x_filename = self.rh.headers.get('X-File-Name')
        if x_filename:
            filename = urllib.parse.unquote(x_filename)
            server_logger.debug(f"Filename from X-File-Name header: {filename}")
        
        # 2. 从 URL path 获取
        if not filename:
            path = urllib.parse.unquote(self.rh.path).lstrip('/')
            # 排除 API 路径
            if path and path not in ['', 'upload', 'api', 'api/upload', 'api/files']:
                filename = path
                server_logger.debug(f"Filename from URL path: {filename}")
        
        # 3. 默认文件名
        if not filename:
            from datetime import datetime
            ext = '.bin'
            # 根据 Content-Type 猜测扩展名
            if 'text/plain' in content_type:
                ext = '.txt'
            elif 'image/jpeg' in content_type:
                ext = '.jpg'
            elif 'image/png' in content_type:
                ext = '.png'
            elif 'application/pdf' in content_type:
                ext = '.pdf'
            
            filename = f"upload_{datetime.now().strftime('%Y%m%d_%H%M%S')}{ext}"
            server_logger.debug(f"Using default filename: {filename}")
        
        server_logger.info(f"Starting raw upload: {filename}, {length} bytes, type={content_type}")
        
        # 根据 Content-Type 选择处理方式
        if content_type.startswith('multipart/form-data'):
            self.handle_multipart_upload(content_type, length)
        else:
            self.save_upload_raw(filename, self.rh.rfile, length)
    
    def save_upload_raw(self, filename: str, stream, length: int):
        """保存原始POST数据"""
        upload_dir = Path(SERVER_CONFIG["directory"])
        upload_dir.mkdir(parents=True, exist_ok=True)
        
        # 安全检查文件名
        safe_name = self._safe_filename(filename)
        if not safe_name:
            # 生成默认文件名
            from datetime import datetime
            safe_name = f"upload_{datetime.now().strftime('%Y%m%d_%H%M%S')}.bin"
            server_logger.warning(f"Invalid filename '{filename}', using default: {safe_name}")
        
        # 处理重名
        target = upload_dir / safe_name
        counter = 1
        original = target
        while target.exists():
            stem = original.stem
            suffix = original.suffix
            target = original.with_name(f"{stem}_{counter}{suffix}")
            counter += 1
        
        server_logger.info(f"Saving upload to: {target} ({length} bytes)")
        
        received = 0
        chunk_size = SERVER_CONFIG["chunk_size"]
        
        try:
            with open(target, 'wb') as f:
                while received < length:
                    to_read = min(chunk_size, length - received)
                    data = stream.read(to_read)
                    
                    if not data:
                        raise IOError(f"Connection closed at {received}/{length} bytes")
                    
                    f.write(data)
                    received += len(data)
                    
                    # 每10MB记录进度
                    if received % (10*1024*1024) == 0:
                        server_logger.debug(f"Progress: {received}/{length} ({received*100//length}%)")
            
            # 验证完整性
            if received != length:
                target.unlink()
                raise IOError(f"Size mismatch: received {received}, expected {length}")
            
            server_logger.info(f"Upload complete: {target.name} ({received} bytes)")
            
            # 返回成功响应
            self.rh.send_response(200)
            self.rh.send_header('Content-Type', 'text/plain')
            response = f"OK {target.name} {received}\n"
            self.rh.send_header('Content-Length', str(len(response)))
            self.rh.end_headers()
            self.rh.wfile.write(response.encode())
            
        except Exception as e:
            # 清理不完整文件
            if target.exists():
                try:
                    target.unlink()
                    server_logger.debug(f"Cleaned up incomplete file: {target}")
                except:
                    pass
            
            server_logger.error(f"Upload failed: {e}")
            
            # 返回错误响应
            try:
                self.rh.send_response(500)
                self.rh.send_header('Content-Type', 'text/plain')
                error_msg = f"ERROR: {str(e)}\n"
                self.rh.send_header('Content-Length', str(len(error_msg)))
                self.rh.end_headers()
                self.rh.wfile.write(error_msg.encode())
            except:
                pass  # 如果连接已断开，忽略错误
            
            raise

    def do_delete(self):
        """DELETE - 删除文件"""
        if self.role == "readonly":
            self.send_error(403, "Read-only user cannot delete")
            return
        
        if not SERVER_CONFIG["enable_delete"]:
            self.send_error(403, "Delete disabled")
            return
        
        filename = urllib.parse.unquote(self.rh.path).lstrip('/')
        self.delete_file(filename)
    
    def do_head(self):
        """HEAD - 获取文件信息"""
        path = urllib.parse.unquote(self.rh.path).lstrip('/')
        
        file_path = self._safe_path(path)
        if not file_path or not file_path.exists():
            self.rh.send_response(404)
            self.rh.end_headers()
            return
        
        self.rh.send_response(200)
        self.rh.send_header('Content-Type', 'application/octet-stream')
        self.rh.send_header('Content-Length', str(file_path.stat().st_size))
        self.rh.send_header('Last-Modified', self._format_time(file_path.stat().st_mtime))
        self.rh.end_headers()
    
    def list_files(self):
        """列出文件"""
        UPLOAD_DIR.mkdir(exist_ok=True)
        
        files = []
        for f in UPLOAD_DIR.iterdir():
            if f.is_file():
                stat = f.stat()
                files.append({
                    "name": f.name,
                    "size": stat.st_size,
                    "size_human": self._human_size(stat.st_size),
                    "modified": self._format_time(stat.st_mtime),
                    "url": f"/{urllib.parse.quote(f.name)}"
                })
        
        # 排序：新文件在前
        files.sort(key=lambda x: x["modified"], reverse=True)
        
        self.send_json({
            "count": len(files),
            "files": files,
            "user": self.username,
            "role": self.role
        })
    
    def download_file(self, filename: str):
        """下载文件"""
        file_path = self._safe_path(filename)
        if not file_path:
            self.send_error(403, "Invalid path")
            return
        
        if not file_path.exists():
            self.send_error(404, "File not found")
            return
        
        file_size = file_path.stat().st_size
        
        # 支持断点续传
        range_header = self.rh.headers.get('Range')
        if range_header:
            try:
                # Range: bytes=start-end
                start, end = self._parse_range(range_header, file_size)
                self.rh.send_response(206)  # Partial Content
                self.rh.send_header('Content-Range', f'bytes {start}-{end}/{file_size}')
                length = end - start + 1
            except ValueError:
                self.rh.send_response(200)
                start, end = 0, file_size - 1
                length = file_size
        else:
            self.rh.send_response(200)
            start, end = 0, file_size - 1
            length = file_size
        
        self.rh.send_header('Content-Type', 'application/octet-stream')
        self.rh.send_header('Content-Disposition', f'attachment; filename="{filename}"')
        self.rh.send_header('Content-Length', str(length))
        self.rh.send_header('Accept-Ranges', 'bytes')
        self.rh.end_headers()
        
        # 发送文件
        with open(file_path, 'rb') as f:
            if start > 0:
                f.seek(start)
            
            remaining = length
            while remaining > 0:
                chunk_size = min(SERVER_CONFIG["chunk_size"], remaining)
                data = f.read(chunk_size)
                if not data:
                    break
                self.rh.wfile.write(data)
                remaining -= len(data)
        
        upload_logger.info(f"Download: {filename} ({length} bytes) by {self.username}")
    
    def save_upload(self, filename: str, stream, length: int):
        """保存上传文件 - 修复版"""
        upload_dir = Path(SERVER_CONFIG["directory"])
        upload_dir.mkdir(parents=True, exist_ok=True)
        
        # 安全检查文件名
        safe_name = self._safe_filename(filename)
        if not safe_name:
            self.send_error(400, "Invalid filename")
            return
        
        # 处理重名
        target = upload_dir / safe_name
        counter = 1
        original = target
        while target.exists():
            stem = original.stem
            suffix = original.suffix
            target = original.with_name(f"{stem}_{counter}{suffix}")
            counter += 1
        
        server_logger.info(f"Starting upload: {target.name} ({length} bytes) from {self.username}")
        
        # 写入文件 - 使用更健壮的读取
        received = 0
        chunk_size = SERVER_CONFIG["chunk_size"]
        
        try:
            with open(target, 'wb') as f:
                while received < length:
                    # 计算本次读取大小
                    to_read = min(chunk_size, length - received)
                    
                    # 读取数据（可能一次读不到to_read字节）
                    data = stream.read(to_read)
                    if not data:
                        # 连接断开
                        raise IOError(f"Connection closed unexpectedly at {received}/{length} bytes")
                    
                    f.write(data)
                    received += len(data)
                    
                    # 每10MB记录一次进度
                    if received % (10*1024*1024) == 0:
                        server_logger.debug(f"Upload progress: {received}/{length} ({received*100//length}%)")
            
            # 验证完整性
            if received != length:
                # 删除不完整文件
                target.unlink()
                raise IOError(f"Size mismatch: received {received}, expected {length}")
            
            # 成功响应
            server_logger.info(f"Upload complete: {target.name} ({received} bytes)")
            
            self.send_json({
                "success": True,
                "filename": target.name,
                "size": received,
                "url": f"/{urllib.parse.quote(target.name)}"
            })
            
        except Exception as e:
            # 清理不完整文件
            if target.exists():
                try:
                    target.unlink()
                except:
                    pass
            
            server_logger.error(f"Upload failed: {e}")
            self.send_error(500, f"Upload failed: {str(e)}")
            raise
    
    def handle_multipart(self, content_type: str, length: int):
        """
        处理 multipart/form-data 上传
        注意：C语言的libcurl multipart需要正确设置 boundary
        """
        server_logger.debug(f"Handling multipart upload, length={length}")
        
        # 使用 cgi 解析（限制内存使用）
        try:
            form = cgi.FieldStorage(
                fp=self.rh.rfile,
                headers=self.rh.headers,
                environ={
                    'REQUEST_METHOD': 'POST',
                    'CONTENT_TYPE': content_type,
                    'CONTENT_LENGTH': str(length),
                },
                keep_blank_values=True,
                strict_parsing=False
            )
        except Exception as e:
            server_logger.error(f"Multipart parse error: {e}")
            self.send_error(400, f"Invalid multipart data: {e}")
            return
        
        # 查找文件字段
        file_item = None
        filename = None
        
        if 'file' in form:
            file_item = form['file']
        else:
            # 查找任何文件类型的字段
            for key in form.keys():
                if hasattr(form[key], 'filename') and form[key].filename:
                    file_item = form[key]
                    break
        
        if not file_item or not hasattr(file_item, 'filename') or not file_item.filename:
            server_logger.warning("No file found in multipart data")
            self.send_error(400, "No file field found. Use 'file' as field name.")
            return
        
        filename = os.path.basename(file_item.filename)
        # 从临时文件读取数据
        if hasattr(file_item, 'file') and file_item.file:
            data = file_item.file.read()
        else:
            data = file_item.value if hasattr(file_item, 'value') else b''
        
        server_logger.info(f"Multipart file: {filename}, size={len(data)}")
        
        # 保存
        from io import BytesIO
        self.save_upload_raw(filename, BytesIO(data), len(data))
    
    def delete_file(self, filename: str):
        """删除文件"""
        file_path = self._safe_path(filename)
        if not file_path:
            self.send_error(403, "Invalid path")
            return
        
        if not file_path.exists():
            self.send_error(404, "File not found")
            return
        
        file_path.unlink()
        upload_logger.info(f"Delete: {filename} by {self.username}")
        
        self.send_json({"success": True, "deleted": filename})
    
    def _safe_path(self, filename: str) -> Optional[Path]:
        """安全检查文件路径，防止目录遍历"""
        try:
            # 清理路径
            filename = filename.replace('\\', '/')
            filename = os.path.normpath(filename)
            filename = filename.lstrip('/')
            
            # 禁止..和隐藏文件
            if '..' in filename or filename.startswith('.'):
                return None
            
            target = (UPLOAD_DIR / filename).resolve()
            target.relative_to(UPLOAD_DIR.resolve())
            return target
        except (ValueError, RuntimeError):
            return None
    
    def _human_size(self, size: int) -> str:
        """人性化文件大小"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} PB"
    
    def _format_time(self, timestamp: float) -> str:
        """格式化时间"""
        from datetime import datetime
        return datetime.fromtimestamp(timestamp).isoformat()
    
    def _parse_range(self, range_header: str, file_size: int) -> Tuple[int, int]:
        """解析Range头"""
        # Range: bytes=0-1023
        if not range_header.startswith('bytes='):
            raise ValueError("Invalid range")
        
        range_str = range_header[6:]
        start_str, end_str = range_str.split('-')
        
        start = int(start_str) if start_str else 0
        end = int(end_str) if end_str else file_size - 1
        
        if start < 0 or end >= file_size or start > end:
            raise ValueError("Invalid range")
        
        return start, end