def handler(request):
    """
    Vercel serverless function handler
    """
    return {
        'statusCode': 200,
        'body': 'Hello from Vercel!'
    } 