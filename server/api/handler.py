from flask import Flask

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def home():
    return "Hello from Vercel!"

@app.route('/api/test', methods=['GET'])
def test():
    return "API is working!"

def handler(request):
    """
    Vercel serverless function handler
    """
    return {
        'statusCode': 200,
        'body': 'Hello from Vercel!'
    } 