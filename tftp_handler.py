#!/usr/bin/env python3
"""
TFTP 服务器处理器
支持 RRQ（读请求）和 WRQ（写请求）
"""

import socket
import struct
import os
from pathlib import Path
from config import SERVER_CONFIG
from logger import server_logger

# TFTP 操作码
OPCODE_RRQ = 1    # 读请求
OPCODE_WRQ = 2    # 写请求
OPCODE_DATA = 3   # 数据
OPCODE_ACK = 4    # 确认
OPCODE_ERROR = 5  # 错误

# TFTP 错误码
ERROR_NOT_DEFINED = 0
ERROR_FILE_NOT_FOUND = 1
ERROR_ACCESS_VIOLATION = 2
ERROR_DISK_FULL = 3
ERROR_ILLEGAL_OPERATION = 4
ERROR_UNKNOWN_TID = 5
ERROR_FILE_EXISTS = 6
ERROR_NO_SUCH_USER = 7

# TFTP 块大小
BLOCK_SIZE = 512
TIMEOUT = 5
MAX_RETRIES = 3


class TFTPServer:
    def __init__(self, host='0.0.0.0', port=69):
        self.host = host
        self.port = port
        self.root_dir = SERVER_CONFIG["directory"][0]
        self.sock = None
        self.running = False
    
    def start(self):
        """启动 TFTP 服务器"""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.running = True
        
        server_logger.info(f"TFTP Server started on {self.host}:{self.port}")
        server_logger.info(f"TFTP root: {self.root_dir}")
        
        while self.running:
            try:
                data, addr = self.sock.recvfrom(1024)
                self.handle_packet(data, addr)
            except Exception as e:
                server_logger.error(f"TFTP error: {e}")
    
    def stop(self):
        """停止 TFTP 服务器"""
        self.running = False
        if self.sock:
            self.sock.close()
    
    def handle_packet(self, data, addr):
        """处理 TFTP 数据包"""
        if len(data) < 2:
            return
        
        opcode = struct.unpack('!H', data[:2])[0]
        
        if opcode == OPCODE_RRQ:
            self.handle_rrq(data[2:], addr)
        elif opcode == OPCODE_WRQ:
            self.handle_wrq(data[2:], addr)
        else:
            self.send_error(addr, 0, "Illegal TFTP operation")
    
    def parse_request(self, data):
        """解析 RRQ/WRQ 请求"""
        parts = data.split(b'\x00')
        if len(parts) < 2:
            return None, None, None
        
        filename = parts[0].decode('utf-8', errors='ignore')
        mode = parts[1].decode('utf-8', errors='ignore').lower()
        
        # 安全检查
        filename = os.path.basename(filename)
        if '..' in filename or filename.startswith('.'):
            return None, None, None
        
        return filename, mode, None
    
    def handle_rrq(self, data, addr):
        """处理读请求（下载）"""
        filename, mode, _ = self.parse_request(data)
        if not filename:
            self.send_error(addr, ERROR_ACCESS_VIOLATION, "Invalid filename")
            return
        
        filepath = self.root_dir / filename
        
        if not filepath.exists() or not filepath.is_file():
            self.send_error(addr, ERROR_FILE_NOT_FOUND, "File not found")
            return
        
        # 创建新的 UDP socket 用于数据传输（避免干扰主端口）
        transfer_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        transfer_sock.settimeout(TIMEOUT)
        
        try:
            with open(filepath, 'rb') as f:
                block_num = 1
                while True:
                    # 读取数据块
                    data_block = f.read(BLOCK_SIZE)
                    
                    # 构建 DATA 包
                    packet = struct.pack('!HH', OPCODE_DATA, block_num) + data_block
                    
                    # 发送并等待 ACK
                    retries = 0
                    while retries < MAX_RETRIES:
                        try:
                            transfer_sock.sendto(packet, addr)
                            ack_data, ack_addr = transfer_sock.recvfrom(1024)
                            
                            if len(ack_data) >= 4:
                                ack_opcode, ack_block = struct.unpack('!HH', ack_data[:4])
                                if ack_opcode == OPCODE_ACK and ack_block == block_num:
                                    break
                        except socket.timeout:
                            retries += 1
                            server_logger.debug(f"TFTP RRQ block {block_num} retry {retries}")
                    
                    if retries >= MAX_RETRIES:
                        server_logger.error(f"TFTP RRQ timeout for {filename}")
                        return
                    
                    # 最后一块（小于 512 字节）
                    if len(data_block) < BLOCK_SIZE:
                        break
                    
                    block_num += 1
            
            server_logger.info(f"TFTP download complete: {filename} to {addr}")
            
        except Exception as e:
            server_logger.error(f"TFTP RRQ error: {e}")
            self.send_error(addr, ERROR_NOT_DEFINED, str(e))
        finally:
            transfer_sock.close()
    
    def handle_wrq(self, data, addr):
        """处理写请求（上传）"""
        filename, mode, _ = self.parse_request(data)
        if not filename:
            self.send_error(addr, ERROR_ACCESS_VIOLATION, "Invalid filename")
            return
        
        filepath = self.root_dir / filename
        
        # 检查文件是否已存在
        if filepath.exists():
            self.send_error(addr, ERROR_FILE_EXISTS, "File already exists")
            return
        
        # 创建新的 UDP socket
        transfer_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        transfer_sock.settimeout(TIMEOUT)
        
        try:
            # 发送 ACK 0 确认 WRQ
            ack_packet = struct.pack('!HH', OPCODE_ACK, 0)
            transfer_sock.sendto(ack_packet, addr)
            
            with open(filepath, 'wb') as f:
                block_num = 1
                while True:
                    # 等待 DATA
                    retries = 0
                    data_packet = None
                    
                    while retries < MAX_RETRIES:
                        try:
                            data_packet, data_addr = transfer_sock.recvfrom(1024)
                            
                            if len(data_packet) >= 4:
                                data_opcode, data_block = struct.unpack('!HH', data_packet[:4])
                                
                                if data_opcode == OPCODE_DATA:
                                    if data_block == block_num:
                                        # 写入数据
                                        f.write(data_packet[4:])
                                        
                                        # 发送 ACK
                                        ack = struct.pack('!HH', OPCODE_ACK, block_num)
                                        transfer_sock.sendto(ack, addr)
                                        
                                        # 检查是否结束
                                        if len(data_packet[4:]) < BLOCK_SIZE:
                                            server_logger.info(f"TFTP upload complete: {filename} from {addr}")
                                            return
                                        
                                        block_num += 1
                                        break
                                    elif data_block < block_num:
                                        # 重复块，重发 ACK
                                        ack = struct.pack('!HH', OPCODE_ACK, data_block)
                                        transfer_sock.sendto(ack, addr)
                                        
                        except socket.timeout:
                            retries += 1
                    
                    if retries >= MAX_RETRIES:
                        server_logger.error(f"TFTP WRQ timeout for {filename}")
                        # 清理不完整文件
                        if filepath.exists():
                            filepath.unlink()
                        return
        
        except Exception as e:
            server_logger.error(f"TFTP WRQ error: {e}")
            # 清理不完整文件
            if filepath.exists():
                filepath.unlink()
            self.send_error(addr, ERROR_NOT_DEFINED, str(e))
        finally:
            transfer_sock.close()
    
    def send_error(self, addr, error_code, error_msg):
        """发送错误包"""
        error_packet = struct.pack('!HH', OPCODE_ERROR, error_code) + error_msg.encode() + b'\x00'
        try:
            self.sock.sendto(error_packet, addr)
        except:
            pass