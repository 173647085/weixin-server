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
    with app.test_client() as test_client:
        response = test_client.get('/')
        return response.get_data(as_text=True) 