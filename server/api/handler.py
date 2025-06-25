from http.server import BaseHTTPRequestHandler
import hashlib
import os
from urllib.parse import parse_qs, urlparse

class handler(BaseHTTPRequestHandler):
    def verify_signature(self, signature, timestamp, nonce):
        """验证签名"""
        token = os.getenv('WEIXIN_TOKEN', 'weixintest123')
        print(f"使用的Token: {token}")
        try:
            if not signature or not timestamp or not nonce:
                print(f"参数不完整: signature={signature}, timestamp={timestamp}, nonce={nonce}")
                return False
                
            # 1. 将token、timestamp、nonce三个参数进行字典序排序
            temp_list = [token, timestamp, nonce]
            temp_list.sort()
            print(f"排序后的列表: {temp_list}")
            
            # 2. 将三个参数字符串拼接成一个字符串进行sha1加密
            temp_str = ''.join(temp_list)
            sign = hashlib.sha1(temp_str.encode('utf-8')).hexdigest()
            print(f"计算的签名: {sign}")
            print(f"收到的签名: {signature}")
            
            # 3. 开发者获得加密后的字符串可与signature对比
            is_valid = sign == signature
            print(f"签名验证结果: {is_valid}")
            return is_valid
        except Exception as e:
            print(f"验证签名异常: {str(e)}")
            return False

    def do_GET(self):
        """处理微信服务器验证请求"""
        try:
            print(f"收到GET请求: {self.path}")
            # 解析URL参数
            parsed_url = urlparse(self.path)
            query_params = parse_qs(parsed_url.query)
            print(f"解析的参数: {query_params}")
            
            # 获取参数
            signature = query_params.get('signature', [''])[0]
            timestamp = query_params.get('timestamp', [''])[0]
            nonce = query_params.get('nonce', [''])[0]
            echostr = query_params.get('echostr', [''])[0]
            
            print(f"准备验证签名: signature={signature}, timestamp={timestamp}, nonce={nonce}, echostr={echostr}")
            
            # 验证签名
            if self.verify_signature(signature, timestamp, nonce):
                print("签名验证成功，返回echostr")
                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(echostr.encode())
            else:
                print("签名验证失败")
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
        print("收到POST请求")
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write('success'.encode()) 