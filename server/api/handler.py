from http.server import BaseHTTPRequestHandler
import hashlib
import os
from urllib.parse import parse_qs, urlparse

class handler(BaseHTTPRequestHandler):
    def verify_signature(self, signature, timestamp, nonce):
        """验证签名"""
        token = os.getenv('WEIXIN_TOKEN', 'weixintest123')
        try:
            if not signature or not timestamp or not nonce:
                return False
                
            # 1. 将token、timestamp、nonce三个参数进行字典序排序
            temp_list = [token, timestamp, nonce]
            temp_list.sort()
            
            # 2. 将三个参数字符串拼接成一个字符串进行sha1加密
            temp_str = ''.join(temp_list)
            sign = hashlib.sha1(temp_str.encode('utf-8')).hexdigest()
            
            # 3. 开发者获得加密后的字符串可与signature对比
            return sign == signature
        except Exception as e:
            print(f"验证签名异常: {str(e)}")
            return False

    def do_GET(self):
        """处理微信服务器验证请求"""
        try:
            # 解析URL参数
            parsed_url = urlparse(self.path)
            query_params = parse_qs(parsed_url.query)
            
            # 获取参数
            signature = query_params.get('signature', [''])[0]
            timestamp = query_params.get('timestamp', [''])[0]
            nonce = query_params.get('nonce', [''])[0]
            echostr = query_params.get('echostr', [''])[0]
            
            # 验证签名
            if self.verify_signature(signature, timestamp, nonce):
                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(echostr.encode())
            else:
                self.send_response(403)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(''.encode())
                
        except Exception as e:
            print(f"处理GET请求异常: {str(e)}")
            self.send_response(500)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(''.encode())
        
    def do_POST(self):
        """处理微信服务器消息请求"""
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write('success'.encode()) 