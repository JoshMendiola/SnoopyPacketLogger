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

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('/var/log/nginx/packet_logger.log')
    ]
)
logger = logging.getLogger('packet_logger')

# Configure JSON logging
log_file = '/var/log/nginx/packet_logger.json'

NGINX_SERVER = "http://nginx:80"
IDS_SERVER = os.getenv('IDS_SERVER')
IDS_PORT = os.getenv('IDS_PORT')

logger.info(f"Initializing IDS client with server {IDS_SERVER}:{IDS_PORT}")
ids_client = IDSClient(IDS_SERVER, IDS_PORT)

def log_entry(data):
    timestamp = datetime.now().isoformat()
    log_data = {
        "timestamp": timestamp,
        **data
    }
    # Write the log entry to the JSON file
    with open(log_file, 'a') as f:
        json.dump(log_data, f)
        f.write('\n')

        logger.info("\n=== Sending Log to IDS Server ===")
        logger.info(f"Timestamp: {timestamp}")
        logger.info(f"IP: {data.get('ip')}")
        logger.info(f"Method: {data.get('method')}")
        logger.info(f"Path: {data.get('path')}")

    if data.get('body'):
        logger.info(f"Body Length: {len(data['body'])} characters")
        # Log first 100 characters of body for visibility
        logger.info(f"Body Preview: {data['body'][:100]}...")

    # Send log to IDS server
    attack_detected, message = ids_client.process_log(log_data)

    if attack_detected:
        logger.warning("\n🚨 ALERT: Potential Attack Detected!")
        logger.warning(f"IDS Message: {message}")
    else:
        logger.info("\n✅ No Attack detected")
        logger.info(f"IDS Message: {message}")

    logger.info("="*50)  # Separator line

def log_request(req):
    logger.info(f"\n>>> New Request: {req.method} {req.full_path}")
    logger.info(f"From IP: {req.remote_addr}")

    headers = dict(req.headers)
    logger.info(f"Headers: {json.dumps(headers, indent=2)}")

    body = req.get_data(as_text=True) if req.method in ['POST', 'PUT', 'PATCH'] else None
    logger.info(f"FULL PATH: {req.full_path}")

    log_data = {
        "type": "REQUEST",
        "ip": req.remote_addr,
        "method": req.method,  # Added missing method
        "path": req.full_path, # Added missing path
        "headers": headers,    # Added missing headers
        "body": body
    }

    log_entry(log_data)

@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def proxy(path):
    start_time = datetime.now()
    logger.info(f"\n=== New Request to {path} ===")

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

        response = Response(resp.content, resp.status_code, headers)

        # Log response info
        processing_time = (datetime.now() - start_time).total_seconds()
        logger.info(f"Request processed in {processing_time:.2f} seconds")
        logger.info(f"Response status: {resp.status_code}")
        logger.info("="*50)

        return response

    except Exception as e:
        logger.error(f"Error processing request: {str(e)}")
        logger.info("="*50)
        return Response("Internal Server Error", status=500)

if __name__ == '__main__':
    logger.info("Starting Packet Logger Service")
    logger.info(f"IDS Server: {IDS_SERVER}:{IDS_PORT}")

    # Ensure the log file exists
    if not os.path.exists(log_file):
        with open(log_file, 'w') as f:
            pass
        logger.info(f"Created log file: {log_file}")

    app.run(host='0.0.0.0', port=5000, debug=False)