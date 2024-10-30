import os
import json
from flask import Flask, request, Response
import requests
from datetime import datetime
from flask_cors import CORS
from ids_client import IDSClient
import logging
from urllib.parse import urlparse, parse_qs
import ids_pb2

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
CLIENT_ID = os.getenv('CLIENT_ID', 'packet_logger_1')

ids_client = IDSClient(IDS_SERVER, IDS_PORT)

def get_formatted_timestamp():
    """Get current timestamp in ISO format"""
    return datetime.now().isoformat()

def format_log_message(ids_response, request_info):
    try:
        if hasattr(ids_response, 'injection_detected'):
            status = "❌" if ids_response.injection_detected else "✅"
            message = ids_response.message
        else:
            status = "✅"
            message = str(ids_response)

        log_line = f"{request_info.get('ip', '-')} - - " \
                   f"[{datetime.now().strftime('%d/%b/%Y %H:%M:%S')}] " \
                   f"\"{request_info.get('method', '-')} {request_info.get('path', '-')} HTTP/1.1\" " \
                   f"{request_info.get('status_code', '-')} -"
        
        return f"{status} REQUEST SENT TO IDS SERVER AND RESPONSE WAS: {message}\n{log_line}"
    except Exception as e:
        logger.error(f"Error formatting log message: {str(e)}")
        return f"Error formatting message: {str(e)}"

def create_log_entry(data):
    """Create a LogEntry that matches the proto definition exactly"""
    try:
        # Convert headers to string dictionary as required by proto
        headers = {
            str(k).lower(): str(v) 
            for k, v in data.get('headers', {}).items()
        }
        
        # Create LogEntry exactly matching proto definition
        return ids_pb2.LogEntry(
            timestamp=get_formatted_timestamp(),
            type="REQUEST",
            ip=data.get('ip', ''),
            method=data.get('method', ''),
            path=data.get('path', ''),
            headers=headers,
            body=data.get('body', ''),
            client_id=CLIENT_ID
        )
    except Exception as e:
        logger.error(f"Error creating log entry: {str(e)}")
        raise

def log_entry(data):
    try:
        # Create log entry for file
        log_data = {
            "timestamp": get_formatted_timestamp(),
            **data
        }
        
        # Write to JSON file
        with open(log_file, 'a') as f:
            json.dump(log_data, f)
            f.write('\n')
        
        # Create and send proto message
        try:
            # Create LogEntry message
            log_entry = create_log_entry(data)
            
            # Send to IDS server
            response = ids_client.process_log(log_entry)
            
            # Log the response
            logger.info(format_log_message(response, data))
            return True, response
            
        except Exception as e:
            logger.error(f"Error communicating with IDS server: {str(e)}")
            return False, ids_pb2.ProcessResult(
                injection_detected=False,
                message=f"Error communicating with IDS server: {str(e)}",
                matched_rules=[]
            )
            
    except Exception as e:
        logger.error(f"Error in log_entry: {str(e)}")
        return False, ids_pb2.ProcessResult(
            injection_detected=False,
            message=f"Error in log processing: {str(e)}",
            matched_rules=[]
        )

def log_request(req):
    try:
        body = req.get_data(as_text=True) if req.method in ['POST', 'PUT', 'PATCH'] else None
        
        request_data = {
            "type": "REQUEST",
            "ip": req.remote_addr,
            "method": req.method,
            "path": req.full_path,
            "headers": dict(req.headers),
            "body": body
        }
        
        return log_entry(request_data)
        
    except Exception as e:
        logger.error(f"Error in log_request: {str(e)}")
        return False, ids_pb2.ProcessResult(
            injection_detected=False,
            message=f"Error processing request: {str(e)}",
            matched_rules=[]
        )

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