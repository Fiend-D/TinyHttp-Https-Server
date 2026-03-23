#!/usr/bin/env python3
"""
主服务器 - 支持HTTP/HTTPS双协议
"""

import http.server
import ssl
import socketserver
import subprocess
import sys
import threading
import socket  # 确保在文件顶部导入
from pathlib import Path

from config import SERVER_CONFIG, BASE_DIR
from logger import server_logger, access_logger
from api_handler import APIHandler
from web_handler import WebHandler


class RequestHandler(http.server.BaseHTTPRequestHandler):
    """统一请求处理器"""
    
    def log_message(self, format, *args):
        """使用自定义日志"""
        access_logger.info(f"{self.client_address[0]} - {format % args}")
    
    def do_GET(self):
        self._route('GET')
    
    def do_POST(self):
        self._route('POST')
    
    def do_PUT(self):
        self._route('PUT')
    
    def do_DELETE(self):
        self._route('DELETE')
    
    def do_HEAD(self):
        self._route('HEAD')
    
    def do_OPTIONS(self):
        """CORS预检"""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Authorization, Content-Type, X-Auth-Token')
        self.end_headers()
    
    def _route(self, method: str):
        """路由分发"""
        path = self.path
        
        # API路径
        if path.startswith('/api/') or path in ['/', '/list', '/logout']:
            if SERVER_CONFIG["enable_web"]:
                handler = WebHandler(self)
                handler.handle(method)
            else:
                self.send_error(404, "Web interface disabled")
            return
        
        # 静态文件
        if path.startswith('/static/'):
            if SERVER_CONFIG["enable_web"]:
                handler = WebHandler(self)
                handler.handle(method)
            else:
                self.send_error(404)
            return
        
        # 文件操作（API风格）
        handler = APIHandler(self)
        handler.handle(method)


def generate_cert():
    """生成SSL证书 - 修复版"""
    cert_file = Path(SERVER_CONFIG["ssl_cert"])
    
    if cert_file.exists():
        # 检查证书是否有效
        try:
            import ssl
            ctx = ssl.SSLContext()
            ctx.load_cert_chain(cert_file)
            server_logger.info(f"Using existing certificate: {cert_file}")
            return True
        except Exception as e:
            server_logger.warning(f"Existing certificate invalid: {e}, regenerating...")
            cert_file.unlink()
    
    server_logger.info("Generating new SSL certificate...")
    try:
        key_file = BASE_DIR / "temp.key"
        crt_file = BASE_DIR / "temp.crt"
        
        # 获取本机IP用于SAN
        import socket
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        
        # 生成证书配置
        san_list = [
            "DNS:localhost",
            "IP:127.0.0.1",
            "IP:::1",
            f"IP:{local_ip}",
            f"DNS:{hostname}",
        ]
        san_str = ",".join(san_list)
        
        # 生成私钥
        subprocess.run([
            'openssl', 'genrsa', '-out', str(key_file), '2048'
        ], check=True, capture_output=True)
        
        # 生成证书请求配置
        conf_file = BASE_DIR / "cert.conf"
        conf_content = f"""
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = localhost

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = {san_str}
"""
        conf_file.write_text(conf_content)
        
        # 生成自签名证书
        subprocess.run([
            'openssl', 'req', '-new', '-x509',
            '-key', str(key_file),
            '-out', str(crt_file),
            '-days', '365',
            '-config', str(conf_file),
            '-extensions', 'v3_req'
        ], check=True, capture_output=True)
        
        # 合并为PEM
        with open(key_file) as f:
            key_data = f.read()
        with open(crt_file) as f:
            crt_data = f.read()
        with open(cert_file, 'w') as f:
            f.write(key_data + crt_data)
        
        # 清理
        key_file.unlink()
        crt_file.unlink()
        conf_file.unlink()
        
        server_logger.info(f"Certificate generated with SAN: {san_str}")
        return True
        
    except Exception as e:
        server_logger.error(f"Certificate generation failed: {e}")
        import traceback
        server_logger.error(traceback.format_exc())
        return False


def run_server(port: int, use_ssl: bool = False):
    """运行单个服务器实例"""
    handler = RequestHandler
    
    class CustomTCPServer(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        
        def server_bind(self):
            super().server_bind()
            import socket
            try:
                self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except:
                pass
    
    with CustomTCPServer(
        (SERVER_CONFIG["host"], port), 
        handler,
        bind_and_activate=False
    ) as httpd:
        
        httpd.server_bind()
        httpd.server_activate()
        
        if use_ssl:
            # 修复：使用更现代的 SSL 上下文
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            # 启用所有 TLS 版本（兼容性）
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.maximum_version = ssl.TLSVersion.MAXIMUM_SUPPORTED
            # 加载证书
            context.load_cert_chain(SERVER_CONFIG["ssl_cert"])
            httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
            
            server_logger.info(f"HTTPS Server on port {port} (TLS 1.2+)")
        else:
            server_logger.info(f"HTTP Server on port {port}")
        
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass


def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(description='File Server with HTTP/HTTPS')
    parser.add_argument('--http', type=int, default=SERVER_CONFIG["http_port"], 
                       help='HTTP port (0 to disable)')
    parser.add_argument('--https', type=int, default=SERVER_CONFIG["https_port"],
                       help='HTTPS port (0 to disable)')
    parser.add_argument('--host', default=SERVER_CONFIG["host"],
                       help='Bind address')
    args = parser.parse_args()
    
    SERVER_CONFIG["http_port"] = args.http
    SERVER_CONFIG["https_port"] = args.https
    SERVER_CONFIG["host"] = args.host
    
    threads = []
    
    # 启动HTTP
    if args.http > 0:
        t = threading.Thread(target=run_server, args=(args.http, False))
        t.daemon = True
        t.start()
        threads.append(t)
        print(f"🌐 HTTP:  http://{args.host}:{args.http}")
    
    # 启动HTTPS
    if args.https > 0:
        t = threading.Thread(target=run_server, args=(args.https, True))
        t.daemon = True
        t.start()
        threads.append(t)
        print(f"🔒 HTTPS: https://{args.host}:{args.https}")
    
    if not threads:
        print("❌ No server started. Use --http or --https")
        sys.exit(1)
    
    print(f"\n📁 Upload directory: {SERVER_CONFIG['directory'][0]}")
    print(f"🔐 Security directory: {SERVER_CONFIG['directory'][1]}")
    print("Press Ctrl+C to stop\n")
    
    try:
        while True:
            import time
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n👋 Shutting down...")


if __name__ == "__main__":
    main()