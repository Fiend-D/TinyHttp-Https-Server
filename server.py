#!/usr/bin/env python3
"""
主服务器 - HTTP/HTTPS + TFTP
"""

import http.server
import ssl
import socketserver
import subprocess
import sys
import threading
import socket
from pathlib import Path

from config import SERVER_CONFIG, BASE_DIR
from logger import server_logger
from api_handler import APIHandler
from web_handler import WebHandler

# 导入 TFTP
try:
    from tftp_handler import TFTPServer
    TFTP_AVAILABLE = True
except ImportError:
    TFTP_AVAILABLE = False
    server_logger.warning("TFTP module not available")


class RequestHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass
    
    def do_GET(self):
        self._route('GET')
    
    def do_POST(self):
        self._route('POST')
    
    def do_PUT(self):
        self._route('PUT')
    
    def do_DELETE(self):
        self._route('DELETE')
    
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Authorization, Content-Type, X-Auth-Token')
        self.end_headers()
    
    def serve_favicon(self):
        """返回 favicon"""
        self.send_response(200)
        self.send_header('Content-Type', 'image/svg+xml')
        self.send_header('Cache-Control', 'public, max-age=86400')
        self.end_headers()
        svg = b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><text y=".9em" font-size="90">&#128193;</text></svg>'
        self.wfile.write(svg)
    
    def _route(self, method: str):
        """路由分发"""
        path = self.path
        
        if path == '/favicon.ico':
            self.serve_favicon()
            return
        
        if path.startswith('/api/') or path in ['/', '/logout'] or path.startswith('/static/'):
            if SERVER_CONFIG["enable_web"]:
                handler = WebHandler(self)
                handler.handle(method)
            else:
                self.send_error(404, "Web interface disabled")
            return
        
        handler = APIHandler(self)
        handler.handle(method)


def generate_cert():
    cert_file = SERVER_CONFIG["ssl_cert"]
    if cert_file.exists():
        return True
    
    server_logger.info("Generating SSL certificate...")
    try:
        key_file = BASE_DIR / "temp.key"
        crt_file = BASE_DIR / "temp.crt"
        
        subprocess.run([
            'openssl', 'req', '-x509', '-newkey', 'rsa:2048',
            '-keyout', str(key_file), '-out', str(crt_file),
            '-days', '365', '-nodes',
            '-subj', '/CN=localhost',
            '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1'
        ], check=True, capture_output=True)
        
        with open(key_file) as f: k = f.read()
        with open(crt_file) as f: c = f.read()
        with open(cert_file, 'w') as f: f.write(k + c)
        
        key_file.unlink()
        crt_file.unlink()
        return True
    except Exception as e:
        server_logger.error(f"Certificate error: {e}")
        return False


def run_server(port, use_ssl=False):
    handler = RequestHandler
    
    class CustomTCPServer(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True
        
        def server_bind(self):
            super().server_bind()
            try:
                self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except:
                pass
    
    if use_ssl:
        if not generate_cert():
            return
    
    with CustomTCPServer((SERVER_CONFIG["host"], port), handler, bind_and_activate=False) as httpd:
        httpd.server_bind()
        httpd.server_activate()
        
        if use_ssl:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(SERVER_CONFIG["ssl_cert"])
            httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
            server_logger.info(f"HTTPS Server on port {port}")
        else:
            server_logger.info(f"HTTP Server on port {port}")
        
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass


def run_tftp(port=69):
    """运行 TFTP 服务器"""
    if not TFTP_AVAILABLE:
        server_logger.error("TFTP not available")
        return
    
    try:
        tftp = TFTPServer(host=SERVER_CONFIG["host"], port=port)
        tftp.start()
    except PermissionError:
        server_logger.error(f"TFTP failed: need root permission for port {port}")
        server_logger.info("Try: sudo setcap cap_net_bind_service=+ep /usr/bin/python3")
    except Exception as e:
        server_logger.error(f"TFTP error: {e}")


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--http', type=int, default=SERVER_CONFIG["http_port"])
    parser.add_argument('--https', type=int, default=SERVER_CONFIG["https_port"])
    parser.add_argument('--tftp', type=int, default=0, help='TFTP port (default: 0=disabled, 69=standard)')
    parser.add_argument('--host', default=SERVER_CONFIG["host"])
    args = parser.parse_args()
    
    SERVER_CONFIG["http_port"] = args.http
    SERVER_CONFIG["https_port"] = args.https
    SERVER_CONFIG["host"] = args.host
    
    threads = []
    
    # HTTP
    if args.http > 0:
        t = threading.Thread(target=run_server, args=(args.http, False))
        t.daemon = True
        t.start()
        threads.append(t)
        print(f"🌐 HTTP:  http://{args.host}:{args.http}")
    
    # HTTPS
    if args.https > 0:
        t = threading.Thread(target=run_server, args=(args.https, True))
        t.daemon = True
        t.start()
        threads.append(t)
        print(f"🔒 HTTPS: https://{args.host}:{args.https}")
    
    # TFTP
    if args.tftp > 0:
        t = threading.Thread(target=run_tftp, args=(args.tftp,))
        t.daemon = True
        t.start()
        threads.append(t)
        print(f"📤 TFTP:  tftp://{args.host}:{args.tftp}")
    
    if not threads:
        print("❌ No server started")
        sys.exit(1)
    
    print(f"\n📁 Upload directory: {SERVER_CONFIG['directory']}")
    print("Press Ctrl+C to stop\n")
    
    try:
        while True:
            import time
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n👋 Stopping...")


if __name__ == "__main__":
    main()