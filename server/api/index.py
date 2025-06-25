from flask import Flask, request
import hashlib
import os
import time
import sys
from pathlib import Path

# 添加父目录到 Python 路径
sys.path.append(str(Path(__file__).parent.parent))
from server import app

def handler(request):
    """
    Vercel Serverless Function handler
    """
    return app