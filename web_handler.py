#!/usr/bin/env python3
"""
Web界面处理器 - 提供浏览器管理界面
"""

import json
import urllib.parse
import cgi
from pathlib import Path

from logger import server_logger, access_logger
from config import SERVER_CONFIG, UPLOAD_DIR, STATIC_DIR, WEB_CONFIG, SECURITY_DIR
from auth import auth_manager, Session


class WebHandler:
    """Web界面处理器"""
    
    def __init__(self, request_handler):
        self.rh = request_handler
        self.username: str = ""
        self.role: str = "guest"
        self.session: Session = None
    
    def check_auth(self) -> bool:
        """检查Web认证（Cookie-based）"""
        cookie_header = self.rh.headers.get('Cookie', '')
        
        # 调试：打印所有 headers
        server_logger.debug(f"Checking auth for {self.rh.path}")
        server_logger.debug(f"Cookie header: {repr(cookie_header)}")
        
        token = None
        if cookie_header:
            for item in cookie_header.split(';'):
                item = item.strip()
                if item.startswith('session='):
                    token = item[8:]  # 提取 token 值
                    break
        
        if not token:
            server_logger.debug(f"No session token found in cookie")
            return False
        
        server_logger.debug(f"Found token: {token[:8]}...")
        
        result = auth_manager.verify_token(token)
        if result:
            self.username, self.role = result
            server_logger.debug(f"Token valid: {self.username} ({self.role})")
            return True
        
        server_logger.debug(f"Token invalid or expired")
        return False
    
    def handle(self, method: str):
        """处理Web请求"""
        # 调试所有请求
        server_logger.debug(f"Web {method} {self.rh.path} | Cookie: {self.rh.headers.get('Cookie', 'None')[:50]}...")
        path = urllib.parse.unquote(self.rh.path)
        
        # 公开资源
        if path.startswith('/static/'):
            self.serve_static(path[8:])  # 移除 /static/
            return
        
        # 登录API
        if path == '/api/login':
            if method == 'POST':
                self.handle_login()
            else:
                self.rh.send_response(405)
                self.rh.end_headers()
            return
        
        # 登出
        if path == '/logout':
            self.handle_logout()
            return
        
        # 需要认证的路径
        if not self.check_auth():
            if path.startswith('/api/'):
                self.send_json({"error": "Unauthorized"}, 401)
            else:
                self.serve_login_page()
            return
        
        # 已认证，更新session
        if self.session:
            self.session.touch()
        
        # API路由
        if path.startswith('/api/'):
            self.handle_api(method, path[5:])  # 移除 /api/
            return
        
        # 页面路由
        if path in ['/', '/index', '/index.html']:
            self.serve_index()
        else:
            self.rh.send_error(404)
    
    def handle_login(self):
        """处理登录"""
        content_type = self.rh.headers.get('Content-Type', '')
        
        # 解析用户名密码...
        if content_type == 'application/json':
            length = int(self.rh.headers.get('Content-Length', 0))
            body = self.rh.rfile.read(length).decode()
            data = json.loads(body)
            username = data.get('username', '')
            password = data.get('password', '')
        else:
            form = cgi.FieldStorage(...)
            username = form.getvalue('username', '')
            password = form.getvalue('password', '')
        
        # 验证
        creds = f"{username}:{password}"
        import base64
        auth_header = f"Basic {base64.b64encode(creds.encode()).decode()}"
        result = auth_manager.verify_basic_auth(auth_header)
        
        if result:
            username, role = result
            token = auth_manager.create_session(username)
            
            # === 关键：设置 Cookie ===
            self.rh.send_response(200)
            self.rh.send_header('Content-type', 'application/json')
            
            # Cookie 格式（兼容手机浏览器）
            cookie = f'session={token}; Path=/; Max-Age=3600; HttpOnly; SameSite=Lax'
            
            # 检测是否是 HTTPS
            # 方法1：通过 server 的 socket 类型判断
            is_https = False
            try:
                import ssl
                # 检查 server 的 socket 是否是 SSL socket
                server_socket = getattr(self.rh.server, 'socket', None)
                if server_socket and isinstance(server_socket, ssl.SSLSocket):
                    is_https = True
            except:
                pass
            
            if is_https:
                cookie += '; Secure'
            
            self.rh.send_header('Set-Cookie', cookie)
            
            # 禁用缓存
            self.rh.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
            self.rh.send_header('Pragma', 'no-cache')
            
            self.rh.end_headers()
            
            response = {
                "success": True,
                "username": username,
                "role": role
            }
            self.rh.wfile.write(json.dumps(response).encode())
            
            access_logger.info(f"Web login success: {username}, cookie set: {cookie[:50]}...")
        else:
            self.rh.send_response(401)
            self.rh.send_header('Content-type', 'application/json')
            self.rh.end_headers()
            self.rh.wfile.write(json.dumps({
                "success": False,
                "error": "Invalid credentials"
            }).encode())
            access_logger.warning(f"Web login failed: {username}")
    
    def handle_logout(self):
        """处理登出"""
        cookie = self.rh.headers.get('Cookie', '')
        token = None
        for item in cookie.split(';'):
            if item.strip().startswith('session='):
                token = item.strip()[8:]
                break
        
        if token:
            auth_manager.destroy_session(token)
        
        self.rh.send_response(302)
        self.rh.send_header('Location', '/')
        self.rh.send_header('Set-Cookie', 'session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0')
        self.rh.end_headers()
    
    def handle_api(self, method: str, endpoint: str):
        """处理Web API"""
        if endpoint == 'files':
            if method == 'GET':
                self.api_list_files()
            elif method == 'POST':
                self.api_upload()
            else:
                self.send_json({"error": "Method not allowed"}, 405)
        elif endpoint.startswith('files/'):
            filename = urllib.parse.unquote(endpoint[6:])
            if method == 'DELETE':
                self.api_delete(filename)
            elif method == 'GET':
                self.api_download(filename)
            else:
                self.send_json({"error": "Method not allowed"}, 405)
        else:
            self.send_json({"error": "Not found"}, 404)
    
    def api_list_files(self):
        """API: 列出文件"""
        files_path = UPLOAD_DIR
        if self.role == "security":
            files_path = SECURITY_DIR
        files_path.mkdir(exist_ok=True)
        
        files = []
        for f in files_path.iterdir():
            if f.is_file():
                stat = f.stat()
                files.append({
                    "name": f.name,
                    "size": stat.st_size,
                    "size_human": self._human_size(stat.st_size),
                    "modified": stat.st_mtime,
                    "modified_iso": self._format_time(stat.st_mtime)
                })
        
        files.sort(key=lambda x: x["modified"], reverse=True)
        
        self.send_json({
            "files": files,
            "count": len(files),
            "user": self.username,
            "role": self.role
        })
    
    def api_upload(self):
        """API: 上传文件"""
        if self.role == "readonly":
            self.send_json({"error": "Read-only"}, 403)
            return
        
        content_type = self.rh.headers.get('Content-Type', '')
        
        if not content_type.startswith('multipart/form-data'):
            self.send_json({"error": "Invalid content type"}, 400)
            return
        
        form = cgi.FieldStorage(
            fp=self.rh.rfile,
            headers=self.rh.headers,
            environ={'REQUEST_METHOD': 'POST'}
        )
        
        if 'file' not in form:
            self.send_json({"error": "No file"}, 400)
            return
        
        file_item = form['file']
        if not file_item.filename:
            self.send_json({"error": "Empty filename"}, 400)
            return
        
        filename = os.path.basename(file_item.filename)
        data = file_item.file.read()
        
        if len(data) > SERVER_CONFIG["max_upload_size"]:
            self.send_json({"error": "File too large"}, 413)
            return
        
        # 安全检查
        safe_name = self._safe_filename(filename)
        if not safe_name:
            self.send_json({"error": "Invalid filename"}, 400)
            return
        
        # 保存
        target = UPLOAD_DIR / safe_name
        if self.role == "security":
            target = SECURITY_DIR / safe_name
        counter = 1
        original = target
        while target.exists():
            stem = original.stem
            suffix = original.suffix
            target = original.with_name(f"{stem}_{counter}{suffix}")
            counter += 1
        
        with open(target, 'wb') as f:
            f.write(data)
        
        server_logger.info(f"Web upload: {target.name} by {self.username}")
        
        self.send_json({
            "success": True,
            "filename": target.name,
            "size": len(data)
        })
    
    def api_delete(self, filename: str):
        """API: 删除文件"""
        if self.role == "readonly":
            self.send_json({"error": "Read-only"}, 403)
            return
        
        if not SERVER_CONFIG["enable_delete"]:
            self.send_json({"error": "Delete disabled"}, 403)
            return
        
        safe_name = self._safe_filename(filename)
        if not safe_name:
            self.send_json({"error": "Invalid filename"}, 400)
            return
        target = UPLOAD_DIR / safe_name
        if self.role == "security":
            target = SECURITY_DIR / safe_name
        if not target.exists():
            self.send_json({"error": "Not found"}, 404)
            return
        
        target.unlink()
        server_logger.info(f"Web delete: {filename} by {self.username}")
        
        self.send_json({"success": True})
    
    def api_download(self, filename: str):
        """API: 下载文件（Web界面用）"""
        safe_name = self._safe_filename(filename)
        if not safe_name:
            self.send_json({"error": "Invalid filename"}, 400)
            return
        
        target = UPLOAD_DIR / safe_name
        if self.role == "security":
            target = SECURITY_DIR / safe_name
        if not target.exists():
            self.send_json({"error": "Not found"}, 404)
            return
        
        self.rh.send_response(200)
        self.rh.send_header('Content-Type', 'application/octet-stream')
        self.rh.send_header('Content-Disposition', f'attachment; filename="{safe_name}"')
        self.rh.send_header('Content-Length', str(target.stat().st_size))
        self.rh.end_headers()
        
        with open(target, 'rb') as f:
            import shutil
            shutil.copyfileobj(f, self.rh.wfile)
    
    def serve_static(self, path: str):
        """提供静态文件"""
        # 安全路径检查
        if '..' in path or path.startswith('.'):
            self.rh.send_error(403)
            return
        
        file_path = STATIC_DIR / path
        
        # 默认文件
        if file_path.is_dir():
            file_path = file_path / 'index.html'
        
        if not file_path.exists() or not file_path.is_file():
            self.rh.send_error(404)
            return
        
        # MIME类型
        mime_types = {
            '.html': 'text/html',
            '.css': 'text/css',
            '.js': 'application/javascript',
            '.json': 'application/json',
            '.png': 'image/png',
            '.jpg': 'image/jpeg',
            '.gif': 'image/gif',
            '.svg': 'image/svg+xml',
            '.ico': 'image/x-icon',
        }
        ext = file_path.suffix.lower()
        content_type = mime_types.get(ext, 'application/octet-stream')
        
        self.rh.send_response(200)
        self.rh.send_header('Content-Type', content_type)
        self.rh.send_header('Content-Length', str(file_path.stat().st_size))
        self.rh.end_headers()
        
        with open(file_path, 'rb') as f:
            self.rh.wfile.write(f.read())
    
    def serve_login_page(self):
        """提供登录页面"""
        html = self._get_login_html()
        self.rh.send_response(200)
        self.rh.send_header('Content-Type', 'text/html; charset=utf-8')
        self.rh.end_headers()
        self.rh.wfile.write(html.encode())
    
    def serve_index(self):
        """提供主页面"""
        html = self._get_index_html()
        self.rh.send_response(200)
        self.rh.send_header('Content-Type', 'text/html; charset=utf-8')
        self.rh.end_headers()
        self.rh.wfile.write(html.encode())
    
    def send_json(self, data: dict, status: int = 200):
        """发送JSON"""
        self.rh.send_response(status)
        self.rh.send_header('Content-Type', 'application/json')
        self.rh.end_headers()
        self.rh.wfile.write(json.dumps(data).encode())
    
    def _safe_filename(self, filename: str) -> str:
        """安全文件名"""
        filename = filename.replace('\\', '/')
        filename = os.path.basename(filename)
        if '..' in filename or filename.startswith('.'):
            return None
        return filename
    
    def _human_size(self, size: int) -> str:
        """人性化大小"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"
    
    def _format_time(self, timestamp: float) -> str:
        """格式化时间"""
        from datetime import datetime
        return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
    
    def _get_login_html(self) -> str:
        """登录页面HTML"""
        return """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - File Server</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .login-box {
            background: white;
            padding: 40px;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            width: 90%;
            max-width: 400px;
        }
        h1 { color: #333; margin-bottom: 30px; text-align: center; }
        .input-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 8px; color: #555; font-size: 14px; }
        input {
            width: 100%;
            padding: 12px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-size: 16px;
            transition: border-color 0.3s;
        }
        input:focus { outline: none; border-color: #667eea; }
        button {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s;
        }
        button:hover { transform: translateY(-2px); }
        .error {
            color: #e74c3c;
            text-align: center;
            margin-top: 15px;
            font-size: 14px;
            display: none;
        }
    </style>
</head>
<body>
    <div class="login-box">
        <h1>🔐 File Server</h1>
        <form id="loginForm">
            <div class="input-group">
                <label>Username</label>
                <input type="text" id="username" required autofocus>
            </div>
            <div class="input-group">
                <label>Password</label>
                <input type="password" id="password" required>
            </div>
            <button type="submit">Sign In</button>
            <div class="error" id="error"></div>
        </form>
    </div>
    <script>
        document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const errorDiv = document.getElementById('error');
    
    errorDiv.style.display = 'none';
    errorDiv.textContent = '';
    
    try {
        console.log('Attempting login...');
        
        const res = await fetch('/api/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({username, password}),
            credentials: 'include'  // 关键：确保发送/接收 cookie
        });
        
        console.log('Response status:', res.status);
        console.log('Response headers:', [...res.headers.entries()]);
        
        // 检查 Set-Cookie 头（调试用）
        const setCookie = res.headers.get('Set-Cookie');
        console.log('Set-Cookie header:', setCookie);
        
        const data = await res.json();
        console.log('Response data:', data);
        
        if (res.ok && data.success) {
            console.log('Login success, redirecting...');
            // 强制跳转，替换历史记录
            window.location.replace('/');
        } else {
            errorDiv.style.display = 'block';
            errorDiv.textContent = data.error || 'Login failed';
        }
    } catch (err) {
        console.error('Login error:', err);
        errorDiv.style.display = 'block';
        errorDiv.textContent = 'Network error: ' + err.message;
    }
});
    </script>
</body>
</html>"""
    
    def _get_index_html(self) -> str:
        """主页面HTML"""
        return """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>File Server</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f5f7fa;
            min-height: 100vh;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px 40px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .header h1 { font-size: 24px; }
        .user-info { display: flex; align-items: center; gap: 20px; }
        .logout-btn {
            background: rgba(255,255,255,0.2);
            color: white;
            border: 1px solid rgba(255,255,255,0.3);
            padding: 8px 20px;
            border-radius: 20px;
            cursor: pointer;
            text-decoration: none;
            font-size: 14px;
        }
        .container {
            max-width: 1200px;
            margin: 40px auto;
            padding: 0 20px;
        }
        .upload-zone {
            background: white;
            border-radius: 16px;
            padding: 40px;
            text-align: center;
            box-shadow: 0 4px 20px rgba(0,0,0,0.05);
            margin-bottom: 30px;
            border: 3px dashed #e0e0e0;
            transition: all 0.3s;
        }
        .upload-zone.dragover {
            border-color: #667eea;
            background: #f8f9ff;
        }
        .upload-zone h2 { margin-bottom: 20px; color: #333; }
        .file-input { display: none; }
        .upload-btn {
            display: inline-block;
            padding: 12px 30px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-radius: 25px;
            cursor: pointer;
            font-weight: 500;
        }
        .progress-bar {
            width: 100%;
            height: 4px;
            background: #e0e0e0;
            border-radius: 2px;
            margin-top: 20px;
            overflow: hidden;
            display: none;
        }
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #667eea, #764ba2);
            width: 0%;
            transition: width 0.3s;
        }
        .file-list {
            background: white;
            border-radius: 16px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.05);
            overflow: hidden;
        }
        .file-list-header {
            background: #f8f9fa;
            padding: 20px 30px;
            border-bottom: 1px solid #e0e0e0;
            display: flex;
            justify-content: space-between;
        }
        .file-item {
            padding: 20px 30px;
            border-bottom: 1px solid #f0f0f0;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .file-item:hover { background: #f8f9fa; }
        .file-info { flex: 1; }
        .file-name { font-weight: 500; color: #333; word-break: break-all; }
        .file-meta { color: #999; font-size: 13px; margin-top: 4px; }
        .file-actions { display: flex; gap: 10px; }
        .btn {
            padding: 8px 16px;
            border-radius: 6px;
            text-decoration: none;
            font-size: 14px;
            cursor: pointer;
            border: none;
        }
        .btn-download { background: #e3f2fd; color: #1976d2; }
        .btn-delete { background: #ffebee; color: #c62828; }
        .empty { padding: 60px; text-align: center; color: #999; }
        .readonly-badge {
            background: #fff3e0;
            color: #e65100;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>📁 File Server</h1>
        <div class="user-info">
            <span id="userInfo">Loading...</span>
            <a href="/logout" class="logout-btn">Logout</a>
        </div>
    </div>
    
    <div class="container">
        <div class="upload-zone" id="dropZone">
            <h2>📤 Upload Files</h2>
            <p style="color: #666; margin-bottom: 20px;">Drag & drop or click to browse</p>
            <label class="upload-btn" id="uploadBtn">
                Choose Files
                <input type="file" class="file-input" id="fileInput" multiple>
            </label>
            <div class="progress-bar" id="progressBar">
                <div class="progress-fill" id="progressFill"></div>
            </div>
        </div>
        
        <div class="file-list">
            <div class="file-list-header">
                <h3>Files</h3>
                <span id="fileCount">0 items</span>
            </div>
            <div id="fileList"></div>
        </div>
    </div>

    <script>
        let userRole = 'guest';
        
        // 加载文件列表
        async function loadFiles() {
            try {
                const res = await fetch('/api/files');
                const data = await res.json();
                
                userRole = data.role;
                document.getElementById('userInfo').innerHTML = 
                    `Welcome, <strong>${data.user}</strong>` +
                    (data.role === 'readonly' ? ' <span class="readonly-badge">READ ONLY</span>' : '');
                
                // 只读用户隐藏上传
                if (data.role === 'readonly') {
                    document.getElementById('dropZone').style.display = 'none';
                }
                
                renderFiles(data.files);
            } catch (err) {
                console.error('Failed to load files:', err);
            }
        }
        
        function renderFiles(files) {
            const container = document.getElementById('fileList');
            document.getElementById('fileCount').textContent = `${files.length} items`;
            
            if (files.length === 0) {
                container.innerHTML = '<div class="empty">No files yet</div>';
                return;
            }
            
            container.innerHTML = files.map(f => `
                <div class="file-item">
                    <div class="file-info">
                        <div class="file-name">${escapeHtml(f.name)}</div>
                        <div class="file-meta">${f.size_human} • ${f.modified_iso}</div>
                    </div>
                    <div class="file-actions">
                        <a href="/api/files/${encodeURIComponent(f.name)}" 
                           class="btn btn-download" download>Download</a>
                        ${userRole !== 'readonly' ? `
                            <button class="btn btn-delete" onclick="deleteFile('${escapeHtml(f.name)}')">Delete</button>
                        ` : ''}
                    </div>
                </div>
            `).join('');
        }
        
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
        
        // 上传
        const dropZone = document.getElementById('dropZone');
        const fileInput = document.getElementById('fileInput');
        const progressBar = document.getElementById('progressBar');
        const progressFill = document.getElementById('progressFill');
        
        dropZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropZone.classList.add('dragover');
        });
        dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
        dropZone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropZone.classList.remove('dragover');
            handleFiles(e.dataTransfer.files);
        });
        fileInput.addEventListener('change', (e) => handleFiles(e.target.files));
        
        function handleFiles(files) {
            Array.from(files).forEach(uploadFile);
        }
        
        function uploadFile(file) {
            const formData = new FormData();
            formData.append('file', file);
            
            progressBar.style.display = 'block';
            
            const xhr = new XMLHttpRequest();
            xhr.upload.addEventListener('progress', (e) => {
                if (e.lengthComputable) {
                    progressFill.style.width = (e.loaded / e.total * 100) + '%';
                }
            });
            xhr.addEventListener('load', () => {
                progressBar.style.display = 'none';
                progressFill.style.width = '0%';
                if (xhr.status === 200) {
                    loadFiles();
                } else {
                    alert('Upload failed');
                }
            });
            xhr.open('POST', '/api/files');
            xhr.send(formData);
        }
        
        // 删除
        async function deleteFile(name) {
            if (!confirm(`Delete "${name}"?`)) return;
            
            try {
                const res = await fetch(`/api/files/${encodeURIComponent(name)}`, {
                    method: 'DELETE'
                });
                if (res.ok) {
                    loadFiles();
                } else {
                    alert('Delete failed');
                }
            } catch (err) {
                alert('Network error');
            }
        }
        
        // 初始化
        loadFiles();
    </script>
</body>
</html>"""