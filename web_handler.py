#!/usr/bin/env python3
"""
Web处理器 - 含最终版HTML，解决所有兼容性问题
"""

import json
import urllib.parse
import cgi
from pathlib import Path
import os

from logger import server_logger, access_logger
from config import SERVER_CONFIG, UPLOAD_DIR, WEB_CONFIG,AUTH_CONFIG
from auth import auth_manager

class WebHandler:
    def __init__(self, request_handler):
        self.rh = request_handler
        self.username = ""
        self.role = "guest"
    
    def check_auth(self) -> bool:
        cookie = self.rh.headers.get('Cookie', '')
        token = None
        
        for item in cookie.split(';'):
            item = item.strip()
            if item.startswith('session='):
                token = item[8:].split(';')[0].strip('"\'')
                break
        
        if token:
            result = auth_manager.verify_token(token)
            if result:
                self.username, self.role = result
                return True
        
        return False
    
    def handle(self, method):
        path = self.rh.path
        
        # 公开资源
        if path == '/favicon.ico':
            self.rh.send_response(204)
            self.rh.end_headers()
            return
        
        # 登录API
        if path == '/api/login':
            if method == 'POST':
                self.handle_login()
            return
        
        # 登出
        if path == '/logout':
            self.handle_logout()
            return
        
        # 静态文件
        if path.startswith('/static/'):
            self.serve_static(path[8:])
            return
        
        # 需要认证
        if not self.check_auth():
            if path.startswith('/api/'):
                self.send_json({"error": "Unauthorized"}, 401)
            else:
                self.serve_login_page()
            return
        
        # API路由
        if path.startswith('/api/'):
            self.handle_api(method, path[5:])
            return
        
        # 页面
        if path in ['/', '/index', '/index.html']:
            self.serve_index()
        else:
            self.rh.send_error(404)
    
    def handle_login(self):
        content_type = self.rh.headers.get('Content-Type', '')
        
        if content_type == 'application/json':
            length = int(self.rh.headers.get('Content-Length', 0))
            body = self.rh.rfile.read(length).decode()
            data = json.loads(body)
            username = data.get('username', '')
            password = data.get('password', '')
        else:
            form = cgi.FieldStorage(
                fp=self.rh.rfile,
                headers=self.rh.headers,
                environ={'REQUEST_METHOD': 'POST'}
            )
            username = form.getvalue('username', '')
            password = form.getvalue('password', '')
        
        # 验证
        import base64
        creds = f"{username}:{password}"
        auth_header = f"Basic {base64.b64encode(creds.encode()).decode()}"
        result = auth_manager.verify_basic_auth(auth_header)
        
        if not result:
            self.rh.send_response(401)
            self.rh.send_header('Content-type', 'application/json')
            self.rh.end_headers()
            self.rh.wfile.write(json.dumps({"success": False, "error": "Invalid credentials"}).encode())
            return
        
        username, role = result
        token = auth_manager.create_session(username)
        
        # 检测HTTPS
        is_https = False
        try:
            import ssl
            server_socket = getattr(self.rh.server, 'socket', None)
            if server_socket and isinstance(server_socket, ssl.SSLSocket):
                is_https = True
        except:
            pass
        
        # 构建Cookie - 最简兼容模式
        cookie = f'session={token}; Path=/; Max-Age=3600'
        if is_https:
            cookie += '; Secure'
        # 不加SameSite，不加HttpOnly（兼容性最好）
        
        self.rh.send_response(200)
        self.rh.send_header('Content-type', 'application/json')
        self.rh.send_header('Set-Cookie', cookie)
        self.rh.send_header('X-Auth-Token', token)  # 备用
        self.rh.end_headers()
        
        self.rh.wfile.write(json.dumps({
            "success": True,
            "username": username,
            "role": role,
            "token": token,
        }).encode())
        
        access_logger.info(f"Web login: {username}")
    
    def handle_logout(self):
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
        self.rh.send_header('Set-Cookie', 'session=; Path=/; Max-Age=0')
        self.rh.end_headers()
    
    def handle_api(self, method, endpoint):
        if endpoint == 'files':
            if method == 'GET':
                self.api_list_files()
            elif method == 'POST':
                self.api_upload()
        elif endpoint.startswith('files/'):
            filename = urllib.parse.unquote(endpoint[6:])
            if method == 'DELETE':
                self.api_delete(filename)
            elif method == 'GET':
                self.api_download(filename)
    
    def api_list_files(self):
        upload_dir = SERVER_CONFIG["directory"][0]  # 默认第一个目录为上传目录
        if self.role == "security":
            upload_dir = SERVER_CONFIG["directory"][1]  # 安全目录
        upload_dir.mkdir(parents=True, exist_ok=True)
        
        files = []
        for f in upload_dir.iterdir():
            if f.is_file():
                stat = f.stat()
                files.append({
                    "name": f.name,
                    "size": stat.st_size,
                    "size_human": self._human_size(stat.st_size),
                    "modified": stat.st_mtime,
                    "modified_iso": self._format_time(stat.st_mtime),
                })
        
        files.sort(key=lambda x: x["modified"], reverse=True)
        
        self.send_json({
            "files": files,
            "count": len(files),
            "user": self.username,
            "role": self.role,
        })
    
    def api_upload(self):
        if not SERVER_CONFIG["enable_upload"]:
            self.send_json({"error": "Upload disabled"}, 403)
            return
        
        content_type = self.rh.headers.get('Content-Type', '')
        
        if content_type.startswith('multipart/form-data'):
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
            
            from io import BytesIO
            self._save_file(filename, BytesIO(data), len(data))
        else:
            self.send_json({"error": "Invalid content type"}, 400)
    
    def api_delete(self, filename):
        if not SERVER_CONFIG["enable_delete"]:
            self.send_json({"error": "Delete disabled"}, 403)
            return
        
        file_path = self._safe_path(filename)
        if not file_path or not file_path.exists():
            self.send_json({"error": "Not found"}, 404)
            return
        
        file_path.unlink()
        self.send_json({"success": True})
    
    def api_download(self, filename):
        file_path = self._safe_path(filename)
        if not file_path or not file_path.exists():
            self.send_json({"error": "Not found"}, 404)
            return
        
        self.rh.send_response(200)
        self.rh.send_header('Content-Type', 'application/octet-stream')
        self.rh.send_header('Content-Disposition', f'attachment; filename="{filename}"')
        self.rh.send_header('Content-Length', str(file_path.stat().st_size))
        self.rh.end_headers()
        
        with open(file_path, 'rb') as f:
            import shutil
            shutil.copyfileobj(f, self.rh.wfile)
    
    def _save_file(self, filename, stream, length):
        upload_dir = SERVER_CONFIG["directory"][0]
        if self.role == "security":
            upload_dir = SERVER_CONFIG["directory"][1]
        upload_dir.mkdir(parents=True, exist_ok=True)
        
        safe_name = self._safe_filename(filename) or f"upload_{int(time.time())}.bin"
        
        target = upload_dir / safe_name
        counter = 1
        original = target
        while target.exists():
            stem = original.stem
            suffix = original.suffix
            target = original.with_name(f"{stem}_{counter}{suffix}")
            counter += 1
        
        with open(target, 'wb') as f:
            f.write(stream.read())
        
        self.send_json({
            "success": True,
            "filename": target.name,
            "size": length,
        })
    
    def _safe_path(self, filename):
        try:
            filename = filename.replace('\\', '/')
            filename = os.path.basename(filename)
            if '..' in filename or filename.startswith('.'):
                return None
            if self.role == "security":
                target = (SERVER_CONFIG["directory"][1] / filename).resolve()
                target.relative_to(SERVER_CONFIG["directory"][1].resolve())
                return target
            else:
                target = (SERVER_CONFIG["directory"][0] / filename).resolve()
                target.relative_to(SERVER_CONFIG["directory"][0].resolve())
                return target
        except:
            return None
    
    def _safe_filename(self, filename):
        if not filename:
            return None
        filename = filename.replace('\\', '/')
        filename = os.path.basename(filename)
        if '..' in filename or filename.startswith('.'):
            return None
        safe_chars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-')
        return ''.join(c for c in filename if c in safe_chars)
    
    def _human_size(self, size):
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"
    
    def _format_time(self, timestamp):
        from datetime import datetime
        return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
    
    def serve_static(self, path):
        self.rh.send_error(404)
    
    def serve_login_page(self):
        html = """<!DOCTYPE html>
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
        }
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
// 安全存储 - 兼容隐私模式
const SafeStorage = {
    _memory: {},
    _available: null,
    
    _check() {
        if (this._available !== null) return this._available;
        try {
            localStorage.setItem('_test_', '1');
            localStorage.removeItem('_test_');
            this._available = true;
        } catch (e) {
            this._available = false;
            console.warn('localStorage unavailable:', e.message);
        }
        return this._available;
    },
    
    get(key) {
        if (this._check()) {
            return localStorage.getItem(key);
        }
        return this._memory[key] || null;
    },
    
    set(key, value) {
        if (this._check()) {
            try {
                localStorage.setItem(key, value);
                return true;
            } catch (e) {
                this._memory[key] = value;
                return false;
            }
        }
        this._memory[key] = value;
        return false;
    },
    
    remove(key) {
        if (this._check()) {
            localStorage.removeItem(key);
        }
        delete this._memory[key];
    }
};

document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const errorDiv = document.getElementById('error');
    
    errorDiv.style.display = 'none';
    
    try {
        const res = await fetch('/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password }),
            credentials: 'include'
        });
        
        const data = await res.json();
        
        if (!res.ok || !data.success) {
            throw new Error(data.error || 'Login failed');
        }
        
        // 保存token（兼容隐私模式）
        if (data.token) {
            SafeStorage.set('fs_token', data.token);
            SafeStorage.set('fs_user', data.username);
        }
        
        window.location.replace('/');
        
    } catch (err) {
        errorDiv.style.display = 'block';
        errorDiv.textContent = err.message;
    }
});
    </script>
</body>
</html>"""
        self.rh.send_response(200)
        self.rh.send_header('Content-Type', 'text/html; charset=utf-8')
        self.rh.end_headers()
        self.rh.wfile.write(html.encode())
    
    def serve_index(self):
        html = """<!DOCTYPE html>
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
        }
        .upload-zone.dragover {
            border-color: #667eea;
            background: #f8f9ff;
        }
        .file-input { display: none; }
        .upload-btn {
            display: inline-block;
            padding: 12px 30px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-radius: 25px;
            cursor: pointer;
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
// ===== 安全存储（兼容隐私模式）=====
const SafeStorage = {
    _memory: {},
    _available: null,
    
    _check() {
        if (this._available !== null) return this._available;
        try {
            localStorage.setItem('_test_', '1');
            localStorage.removeItem('_test_');
            this._available = true;
        } catch (e) {
            this._available = false;
        }
        return this._available;
    },
    
    get(key) {
        if (this._check()) return localStorage.getItem(key);
        return this._memory[key] || null;
    },
    
    set(key, value) {
        if (this._check()) {
            try {
                localStorage.setItem(key, value);
                return true;
            } catch (e) {
                this._memory[key] = value;
                return false;
            }
        }
        this._memory[key] = value;
        return false;
    },
    
    remove(key) {
        if (this._check()) localStorage.removeItem(key);
        delete this._memory[key];
    }
};

// ===== 工具函数 =====
function getAuthToken() {
    return SafeStorage.get('fs_token') || '';
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ===== 渲染函数 =====
function renderFiles(files) {
    const container = document.getElementById('fileList');
    document.getElementById('fileCount').textContent = files.length + ' items';
    
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
                <button class="btn btn-delete" 
                        onclick="deleteFile('${escapeHtml(f.name)}')">Delete</button>
            </div>
        </div>
    `).join('');
}

// ===== 网络请求 =====
async function authFetch(url, options = {}) {
    const token = getAuthToken();
    const headers = { ...options.headers };
    
    if (token) {
        headers['X-Auth-Token'] = token;
    }
    
    try {
        const res = await fetch(url, {
            ...options,
            headers,
            credentials: 'include'
        });
        
        if (res.status === 401) {
            SafeStorage.remove('fs_token');
            SafeStorage.remove('fs_user');
            window.location.href = '/';
            return null;
        }
        
        return res;
    } catch (err) {
        console.error('Request failed:', err);
        throw err;
    }
}

// ===== 业务逻辑 =====
async function loadFiles() {
    try {
        const res = await authFetch('/api/files');
        if (!res) return;
        
        const data = await res.json();
        
        const userInfo = document.getElementById('userInfo');
        if (userInfo && data.user) {
            userInfo.innerHTML = `Welcome, <strong>${data.user}</strong>` +
                (data.role === 'readonly' ? ' <span style="background:#fff3e0;color:#e65100;padding:4px 12px;border-radius:12px;font-size:12px;">READ ONLY</span>' : '');
        }
        
        renderFiles(data.files);
    } catch (err) {
        console.error('Failed to load files:', err);
    }
}

async function uploadFile(file) {
    const formData = new FormData();
    formData.append('file', file);
    
    const token = getAuthToken();
    
    const progressBar = document.getElementById('progressBar');
    const progressFill = document.getElementById('progressFill');
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
        } else if (xhr.status === 401) {
            alert('Session expired');
            SafeStorage.clear && SafeStorage.clear();
            window.location.href = '/';
        } else {
            alert('Upload failed: ' + xhr.statusText);
        }
    });
    
    xhr.addEventListener('error', () => {
        progressBar.style.display = 'none';
        alert('Network error');
    });
    
    xhr.open('POST', '/api/files');
    
    if (token) {
        xhr.setRequestHeader('X-Auth-Token', token);
    }
    
    xhr.send(formData);
}

async function deleteFile(name) {
    if (!confirm(`Delete "${name}"?`)) return;
    
    try {
        const res = await authFetch(`/api/files/${encodeURIComponent(name)}`, {
            method: 'DELETE'
        });
        
        if (res && res.ok) {
            loadFiles();
        }
    } catch (err) {
        alert('Network error');
    }
}

// ===== 事件绑定 =====
const dropZone = document.getElementById('dropZone');
const fileInput = document.getElementById('fileInput');

dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('dragover');
});

dropZone.addEventListener('dragleave', () => {
    dropZone.classList.remove('dragover');
});

dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('dragover');
    if (e.dataTransfer.files.length > 0) {
        Array.from(e.dataTransfer.files).forEach(uploadFile);
    }
});

fileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
        Array.from(e.target.files).forEach(uploadFile);
    }
});

// ===== 初始化 =====
document.addEventListener('DOMContentLoaded', () => {
    loadFiles();
});
    </script>
</body>
</html>"""
        self.rh.send_response(200)
        self.rh.send_header('Content-Type', 'text/html; charset=utf-8')
        self.rh.end_headers()
        self.rh.wfile.write(html.encode())
    
    def send_json(self, data, status=200):
        self.rh.send_response(status)
        self.rh.send_header('Content-Type', 'application/json')
        self.rh.end_headers()
        self.rh.wfile.write(json.dumps(data).encode())