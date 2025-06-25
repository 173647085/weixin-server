from flask import Flask, request
import hashlib
import os
import requests
import json
import xml.etree.ElementTree as ET
import time
from threading import Lock

app = Flask(__name__)

# 使用环境变量获取配置信息
TOKEN = os.getenv('WEIXIN_TOKEN', 'weixintest123')
APPID = os.getenv('WEIXIN_APPID', '')
SECRET = os.getenv('WEIXIN_SECRET', '')

# Access Token 缓存
access_token_cache = {
    'token': None,
    'expire_time': 0
}
token_lock = Lock()

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

def get_access_token():
    """获取access_token，带缓存机制"""
    global access_token_cache
    
    with token_lock:
        current_time = time.time()
        # 如果token未过期，直接返回缓存的token
        if access_token_cache['token'] and current_time < access_token_cache['expire_time']:
            return access_token_cache['token']
            
        try:
            token_url = f"https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid={APPID}&secret={SECRET}"
            response = requests.get(token_url).json()
            
            if 'access_token' in response:
                access_token_cache['token'] = response['access_token']
                # 设置过期时间为7000秒（微信token有效期为7200秒）
                access_token_cache['expire_time'] = current_time + 7000
                return access_token_cache['token']
                
            print(f"获取access_token失败: {response}")
            return None
        except Exception as e:
            print(f"获取access_token异常: {str(e)}")
            return None

def send_custom_message(openid, report_url):
    """发送自定义消息"""
    try:
        access_token = get_access_token()
        if not access_token:
            return False
            
        url = f"https://api.weixin.qq.com/cgi-bin/message/custom/send?access_token={access_token}"
        payload = {
            "touser": openid,
            "msgtype": "text",
            "text": {
                "content": f"您的专属报表已生成，点击查看：{report_url}"
            }
        }
        headers = {'Content-Type': 'application/json'}
        response = requests.post(url, data=json.dumps(payload), headers=headers)
        result = response.json()
        
        if result.get('errcode') == 0:
            return True
        print(f"发送消息失败: {result}")
        return False
    except Exception as e:
        print(f"发送消息异常: {str(e)}")
        return False

def create_reply_xml(to_user, from_user, content):
    """创建回复消息的XML"""
    return f"""<xml>
    <ToUserName><![CDATA[{to_user}]]></ToUserName>
    <FromUserName><![CDATA[{from_user}]]></FromUserName>
    <CreateTime>{int(time.time())}</CreateTime>
    <MsgType><![CDATA[text]]></MsgType>
    <Content><![CDATA[{content}]]></Content>
    </xml>"""

@app.route('/', methods=['GET', 'POST'])
def wechat():
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
        
        # 处理微信消息
        elif request.method == 'POST':
            xml_data = request.data
            if not xml_data:
                return ''
                
            # 解析XML消息
            root = ET.fromstring(xml_data)
            msg_type = root.find('MsgType').text
            from_user = root.find('FromUserName').text
            to_user = root.find('ToUserName').text
            
            # 这里可以根据消息类型处理不同的消息
            if msg_type == 'text':
                content = root.find('Content').text
                if content == '报表':
                    # 这里替换为实际的报表生成逻辑和URL
                    report_url = "https://example.com/report"
                    if send_custom_message(from_user, report_url):
                        return create_reply_xml(from_user, to_user, "报表生成中，请稍候...")
                    else:
                        return create_reply_xml(from_user, to_user, "抱歉，报表生成失败，请稍后重试")
                
                # 默认回复
                return create_reply_xml(from_user, to_user, "您可以发送'报表'查看您的专属报表")
            
            # 其他类型消息的默认回复
            return create_reply_xml(from_user, to_user, "目前仅支持文本消息")
            
    except Exception as e:
        print(f"处理请求异常: {str(e)}")
        return ''

# 云函数入口
def main_handler(event, context):
    return app(event, context)

@app.route('/test')
def test():
    """测试服务器是否正常运行"""
    return "Server is running!"

if __name__ == '__main__':
    # 检查必要的环境变量
    if not APPID or not SECRET:
        print("\n警告: 未设置 WEIXIN_APPID 或 WEIXIN_SECRET 环境变量!")
        print("请设置以下环境变量:")
        print("set WEIXIN_APPID=你的AppID")
        print("set WEIXIN_SECRET=你的Secret")
        print("set WEIXIN_TOKEN=你的Token（可选，默认为weixintest123）\n")
        exit(1)
        
    print(f"\n服务器启动...")
    print(f"Token: {TOKEN}")
    print(f"AppID: {APPID}")
    print(f"监听端口: 5000")
    print("等待请求...\n")
    app.run(host='0.0.0.0', port=5000, debug=True)