import os
import json
from flask import Flask, request, Response
import requests
from datetime import datetime
from flask_cors import CORS
from ids_client import IDSClient
import logging
from urllib.parse import urlparse, parse_qs
import ids_pb2  # Add missing import

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

def format_log_message(ids_response, request_info):
    try:
        # Check if response is a ProcessResult object
        if hasattr(ids_response, 'injection_detected'):
            status = "❌" if ids_response.injection_detected else "✅"
            message = ids_response.message
        else:
            # Handle string responses or other types
            status = "✅"
            message = str(ids_response)

        timestamp = datetime.now().strftime("[%d/%b/%Y %H:%M:%S]")
        ip = request_info.get('ip', '-')
        method = request_info.get('method', '-')
        path = request_info.get('path', '-')
        status_code = request_info.get('status_code', '-')
        
        # Create base message
        msg = f"{status} REQUEST SENT TO IDS SERVER AND RESPONSE WAS: {message}\n" \
              f"{ip} - - {timestamp} \"{method} {path} HTTP/1.1\" {status_code} -"
        
        # Add details for detected attacks
        if hasattr(ids_response, 'injection_detected') and ids_response.injection_detected:
            msg += f"\nRequest Details:\n" \
                   f"IP: {ip}\n" \
                   f"Method: {method}\n" \
                   f"Path: {path}"
            if request_info.get('query_params'):
                msg += f"\nQuery Parameters: {json.dumps(request_info['query_params'], indent=2)}"
        
        return msg
    except Exception as e:
        logger.error(f"Error formatting log message: {str(e)}")
        return f"Error processing request: {str(e)}"

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

def create_default_response():
    """Create a default ProcessResult for error cases"""
    return ids_pb2.ProcessResult(
        injection_detected=False,
        message="Error processing request",
        matched_rules=[]
    )

def log_entry(data):
    try:
        # Ensure timestamp is added to data
        data['timestamp'] = datetime.now().isoformat()
        
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
        try:
            response = ids_client.process_log(data)
            if isinstance(response, tuple) and len(response) == 2:
                _, ids_response = response
            else:
                ids_response = response
            
            # Log formatted message
            logger.info(format_log_message(ids_response, data))
            return True, ids_response
            
        except Exception as e:
            logger.error(f"Error communicating with IDS server: {str(e)}")
            return False, create_default_response()
            
    except Exception as e:
        logger.error(f"Error in log_entry: {str(e)}")
        return False, create_default_response()

def log_request(req):
    try:
        body = req.get_data(as_text=True) if req.method in ['POST', 'PUT', 'PATCH'] else None
        
        request_data = {
            "type": "REQUEST",
            "ip": req.remote_addr,
            "method": req.method,
            "path": req.full_path,
            "headers": dict(req.headers),
            "body": body,
            "timestamp": datetime.now().isoformat()
        }
        
        return log_entry(request_data)
        
    except Exception as e:
        logger.error(f"Error in log_request: {str(e)}")
        return False, create_default_response()

@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def proxy(path):
    try:
        # Log the request first
        success, _ = log_request(request)
        
        # Forward the request to nginx
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
        logger.error(f"Error in proxy route: {str(e)}")
        return Response("Internal Server Error", status=500)

if __name__ == '__main__':
    if not os.path.exists(log_file):
        with open(log_file, 'w') as f:
            pass
    
    app.run(host='0.0.0.0', port=5000, debug=False)