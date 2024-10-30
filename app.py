import os
import json
from flask import Flask, request, Response
import requests
from datetime import datetime
from flask_cors import CORS
from ids_client import IDSClient
import logging
from urllib.parse import urlparse, parse_qs

app = Flask(__name__)
CORS(app)

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

def format_log_message(response, request_info):
    status = "✅" if not response.injection_detected else "❌"
    timestamp = datetime.now().strftime("[%d/%b/%Y %H:%M:%S]")
    ip = request_info.get('ip', '-')
    method = request_info.get('method', '-')
    path = request_info.get('path', '-')
    
    msg = f"{status} REQUEST SENT TO IDS SERVER AND RESPONSE WAS: {response.message}\n" \
          f"{ip} - - {timestamp} \"{method} {path} HTTP/1.1\" {request_info.get('status_code', '-')} -"
    
    if response.injection_detected:
        msg += f"\nRequest Details:\n" \
               f"IP: {ip}\n" \
               f"Method: {method}\n" \
               f"Path: {path}"
        if request_info.get('query_params'):
            msg += f"\nQuery Parameters: {request_info['query_params']}"
    return msg

def process_url(url):
    """Extract and process URL components for analysis"""
    parsed = urlparse(url)
    path = parsed.path
    query_dict = parse_qs(parsed.query)
    
    # Convert query params to json-compatible format
    query_params = {k: v[0] if len(v) == 1 else v for k, v in query_dict.items()}
    
    return {
        "path": path,
        "query_params": query_params,
        "full_path": url
    }

def log_entry(data):
    # Process URL components for GET requests
    if data['method'] == 'GET':
        url_data = process_url(data['path'])
        data.update({
            "analyzed_data": {
                "path_components": url_data['path'].split('/'),
                "query_params": url_data['query_params'],
                "full_path": url_data['full_path']
            }
        })
    else:
        # For POST/PUT/PATCH, include body in analyzed_data
        try:
            body_data = json.loads(data.get('body', '{}'))
            data['analyzed_data'] = body_data
        except json.JSONDecodeError:
            data['analyzed_data'] = {"raw_body": data.get('body', '')}

    # Write to JSON file
    with open(log_file, 'a') as f:
        json.dump(data, f)
        f.write('\n')
    
    # Send log to IDS server
    injection_detected, response = ids_client.process_log(data)
    
    # Log formatted message
    logger.info(format_log_message(response, data))

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
    if not os.path.exists(log_file):
        with open(log_file, 'w') as f:
            pass
    app.run(host='0.0.0.0', port=5000, debug=False)