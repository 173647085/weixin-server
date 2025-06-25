from flask import Flask
import os

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def home():
    return "Hello from Vercel!"

@app.route('/api/test', methods=['GET'])
def test():
    return "API is working!" 