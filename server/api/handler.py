from http.server import BaseHTTPRequestHandler
import hashlib
import os
from urllib.parse import parse_qs, urlparse
import xml.etree.ElementTree as ET
import time

class handler(BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        # 初始化配置
        self.appid = os.getenv('WEIXIN_APPID')
        self.secret = os.getenv('WEIXIN_SECRET')
        self.token = os.getenv('WEIXIN_TOKEN', 'weixintest123')
        print(f"初始化配置: APPID={self.appid}, TOKEN={self.token}")
        super().__init__(*args, **kwargs)

    def verify_signature(self, signature, timestamp, nonce):
        """验证签名"""
        try:
            if not signature or not timestamp or not nonce:
                print(f"参数不完整: signature={signature}, timestamp={timestamp}, nonce={nonce}")
                return False
                
            # 1. 将token、timestamp、nonce三个参数进行字典序排序
            temp_list = [self.token, timestamp, nonce]
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

    def create_reply_xml(self, to_user, from_user, content):
        """创建回复消息的XML"""
        print(f"准备创建回复XML: to_user={to_user}, from_user={from_user}, content={content}")
        reply_xml = f"""<xml>
<ToUserName><![CDATA[{to_user}]]></ToUserName>
<FromUserName><![CDATA[{from_user}]]></FromUserName>
<CreateTime>{int(time.time())}</CreateTime>
<MsgType><![CDATA[text]]></MsgType>
<Content><![CDATA[{content}]]></Content>
</xml>"""
        print(f"生成的回复XML: {reply_xml}")
        return reply_xml

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
        try:
            print("开始处理POST请求...")
            print(f"请求路径: {self.path}")
            print(f"请求头: {self.headers}")
            
            # 验证签名
            parsed_url = urlparse(self.path)
            query_params = parse_qs(parsed_url.query)
            signature = query_params.get('signature', [''])[0]
            timestamp = query_params.get('timestamp', [''])[0]
            nonce = query_params.get('nonce', [''])[0]
            
            if not self.verify_signature(signature, timestamp, nonce):
                print("POST请求签名验证失败")
                self.send_response(403)
                self.end_headers()
                return

            # 获取请求内容长度
            content_length = int(self.headers.get('Content-Length', 0))
            print(f"请求内容长度: {content_length}")
            
            if content_length == 0:
                print("请求内容为空")
                self.send_response(400)
                self.end_headers()
                return

            # 读取XML消息
            message_xml = self.rfile.read(content_length).decode('utf-8')
            print(f"收到的消息XML: {message_xml}")

            # 解析XML
            root = ET.fromstring(message_xml)
            msg_type = root.find('MsgType').text
            from_user = root.find('FromUserName').text
            to_user = root.find('ToUserName').text
            print(f"消息类型: {msg_type}")
            print(f"发送者: {from_user}")
            print(f"接收者: {to_user}")

            reply_content = "您好！我已收到您的消息。"
            
            # 根据消息类型处理
            if msg_type == 'text':
                # 获取用户发送的文本内容
                user_content = root.find('Content').text
                print(f"用户发送的文本内容: {user_content}")
                
                # 根据用户发送的内容定制回复
                if '你好' in user_content:
                    reply_content = '你好！很高兴见到你！'
                elif '帮助' in user_content:
                    reply_content = '这是一个测试公众号，您可以发送以下内容进行测试：\n1. 你好\n2. 帮助\n3. 时间'
                elif '时间' in user_content:
                    reply_content = f'当前时间是：{time.strftime("%Y-%m-%d %H:%M:%S")}'
                
                print(f"准备回复的内容: {reply_content}")

            # 创建回复消息
            reply_xml = self.create_reply_xml(from_user, to_user, reply_content)

            # 发送回复
            print("准备发送回复...")
            self.send_response(200)
            self.send_header('Content-type', 'application/xml')
            self.end_headers()
            self.wfile.write(reply_xml.encode('utf-8'))
            print("回复发送完成")

        except Exception as e:
            print(f"处理POST请求异常: {str(e)}")
            import traceback
            print(f"异常堆栈: {traceback.format_exc()}")
            self.send_response(200)  # 即使发生错误也要返回200
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write('success'.encode()) 