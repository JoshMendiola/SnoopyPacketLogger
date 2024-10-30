import os
import json
from flask import Flask, request, Response
import requests
from datetime import datetime
from flask_cors import CORS
from ids_client import IDSClient
import logging

app = Flask(__name__)
CORS(app)

# Configure logging with a cleaner format
logging.basicConfig(
    level=logging.INFO,
    format='%(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('/var/log/nginx/packet_logger.log')
    ]
)
logger = logging.getLogger('packet_logger')

log_file = '/var/log/nginx/packet_logger.json'
NGINX_SERVER = "http://nginx:80"
IDS_SERVER = os.getenv('IDS_SERVER')
IDS_PORT = os.getenv('IDS_PORT')

ids_client = IDSClient(IDS_SERVER, IDS_PORT)

def log_entry(data):
    timestamp = datetime.now().isoformat()
    log_data = {
        "timestamp": timestamp,
        **data
    }

    # Write to JSON file
    with open(log_file, 'a') as f:
        json.dump(log_data, f)
        f.write('\n')
    
    # Send log to IDS server and get response
    injection_detected, message = ids_client.process_log(log_data)
    
    if injection_detected:
        logger.warning("\n🚨 REQUEST SENT TO IDS SERVER AND RESPONSE WAS: " + message)
        logger.warning("\nRequest Details:")
        logger.warning(f"Timestamp: {timestamp}")
        logger.warning(f"IP: {data.get('ip')}")
        logger.warning(f"Method: {data.get('method')}")
        logger.warning(f"Path: {data.get('path')}")
        if data.get('body'):
            logger.warning(f"Request Body Preview: {data['body'][:100]}...")
    else:
        logger.info("\n✅ REQUEST SENT TO IDS SERVER AND RESPONSE WAS: " + message)

def log_request(req):
    body = req.get_data(as_text=True) if req.method in ['POST', 'PUT', 'PATCH'] else None
    
    log_entry({
        "type": "REQUEST",
        "ip": req.remote_addr,
        "method": req.method,
        "path": req.full_path,
        "headers": dict(req.headers),
        "body": body
    })

@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def proxy(path):
    try:
        log_request(request)
        
        resp = requests.request(
            method=request.method,
            url=f"{NGINX_SERVER}/{path}",
            headers={key: value for (key, value) in request.headers if key != 'Host'},
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False
        )
        
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        headers = [(name, value) for (name, value) in resp.raw.headers.items()
                   if name.lower() not in excluded_headers]
        
        return Response(resp.content, resp.status_code, headers)
        
    except Exception as e:
        logger.error(f"Error processing request: {str(e)}")
        return Response("Internal Server Error", status=500)

if __name__ == '__main__':
    logger.info("Starting Packet Logger Service")
    
    if not os.path.exists(log_file):
        with open(log_file, 'w') as f:
            pass
    
    app.run(host='0.0.0.0', port=5000, debug=False)