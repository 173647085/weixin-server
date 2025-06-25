from flask import Flask, request
import hashlib
import os
import time

app = Flask(__name__)

# 使用环境变量获取配置信息
TOKEN = os.getenv('WEIXIN_TOKEN', 'weixintest123')

def verify_signature(signature, timestamp, nonce):
    """验证签名"""
    try:
        if not signature or not timestamp or not nonce:
            return False
            
        # 1. 将token、timestamp、nonce三个参数进行字典序排序
        temp_list = [TOKEN, timestamp, nonce]
        temp_list.sort()
        
        # 2. 将三个参数字符串拼接成一个字符串进行sha1加密
        temp_str = ''.join(temp_list)
        sign = hashlib.sha1(temp_str.encode('utf-8')).hexdigest()
        
        # 3. 开发者获得加密后的字符串可与signature对比
        return sign == signature
    except Exception as e:
        print(f"验证签名异常: {str(e)}")
        return False

@app.route('/', methods=['GET', 'POST'])
def handle():
    """处理微信服务器的请求"""
    try:
        # 微信服务器验证
        if request.method == 'GET':
            signature = request.args.get('signature', '')
            timestamp = request.args.get('timestamp', '')
            nonce = request.args.get('nonce', '')
            echostr = request.args.get('echostr', '')
            
            if verify_signature(signature, timestamp, nonce):
                return echostr
            return ''
            
        return 'Hello from Flask!'
            
    except Exception as e:
        print(f"处理请求异常: {str(e)}")
        return ''