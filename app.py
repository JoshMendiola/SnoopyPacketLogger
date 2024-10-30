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

ids_client = IDSClient(IDS_SERVER, IDS_PORT)

def get_formatted_timestamp():
    """Get current timestamp in ISO format"""
    return datetime.now().isoformat()

def format_log_entry(timestamp, method, path, status_code='-'):
    """Format timestamp for log entry"""
    return f"{timestamp} \"{method} {path} HTTP/1.1\" {status_code}"

def format_log_message(ids_response, request_info):
    try:
        if hasattr(ids_response, 'injection_detected'):
            status = "❌" if ids_response.injection_detected else "✅"
            message = ids_response.message
        else:
            status = "✅"
            message = str(ids_response)

        # Format the log entry
        log_entry = format_log_entry(
            datetime.now().strftime("[%d/%b/%Y %H:%M:%S]"),
            request_info.get('method', '-'),
            request_info.get('path', '-'),
            request_info.get('status_code', '-')
        )
        
        return f"{status} REQUEST SENT TO IDS SERVER AND RESPONSE WAS: {message}\n" \
               f"{request_info.get('ip', '-')} - - {log_entry}"
    except Exception as e:
        logger.error(f"Error formatting log message: {str(e)}")
        return f"Error formatting message: {str(e)}"

def process_url(url):
    """Extract and process URL components for analysis"""
    try:
        parsed = urlparse(url)
        path_components = [comp for comp in parsed.path.split('/') if comp]
        query_dict = parse_qs(parsed.query)
        
        # Convert query params to simple dict with single values
        query_params = {k: v[0] if len(v) == 1 else v for k, v in query_dict.items()}
        
        return {
            "path_components": path_components,
            "query_params": query_params,
            "raw_path": parsed.path,
            "raw_query": parsed.query
        }
    except Exception as e:
        logger.error(f"Error processing URL: {str(e)}")
        return {"error": str(e)}

def create_analyzable_headers(headers):
    """Convert headers to a simple dict for analysis"""
    return {k.lower(): str(v) for k, v in headers.items()}

def log_entry(data):
    try:
        # Create a serializable analysis object
        analysis_data = {
            "request_time": get_formatted_timestamp(),
            "method": data['method'],
            "ip": data['ip'],
            "url_data": process_url(data['path']),
            "headers": create_analyzable_headers(data.get('headers', {}))
        }

        # Add body analysis for POST/PUT/PATCH
        if data['method'] in ['POST', 'PUT', 'PATCH'] and data.get('body'):
            try:
                analysis_data['body'] = json.loads(data['body'])
            except json.JSONDecodeError:
                analysis_data['body'] = {"raw_content": data['body']}

        # Create log entry
        log_data = {
            "timestamp": get_formatted_timestamp(),
            **data,
            "analyzed_data": analysis_data
        }

        # Write to JSON file
        with open(log_file, 'a') as f:
            json.dump(log_data, f)
            f.write('\n')
        
        # Prepare data for IDS server
        ids_data = {
            "type": "REQUEST",
            "data": json.dumps(analysis_data)  # Convert analysis data to JSON string
        }
        
        # Send to IDS server
        try:
            response = ids_client.process_log(ids_data)
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
            "body": body,
            "timestamp": get_formatted_timestamp()
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