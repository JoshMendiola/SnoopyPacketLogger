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

def format_log_message(ids_response, request_info):
    try:
        if hasattr(ids_response, 'injection_detected'):
            status = "❌" if ids_response.injection_detected else "✅"
            message = ids_response.message
        else:
            status = "✅"
            message = str(ids_response)

        timestamp = datetime.now().strftime("[%d/%b/%Y %H:%M:%S]")
        ip = request_info.get('ip', '-')
        method = request_info.get('method', '-')
        path = request_info.get('path', '-')
        status_code = request_info.get('status_code', '-')
        
        msg = f"{status} REQUEST SENT TO IDS SERVER AND RESPONSE WAS: {message}\n" \
              f"{ip} - - {timestamp} \"{method} {path} HTTP/1.1\" {status_code} -"
        return msg
    except Exception as e:
        logger.error(f"Error formatting log message: {str(e)}")
        return f"Error processing request: {str(e)}"

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
    return {k.lower(): v for k, v in headers.items()}

def log_entry(data):
    try:
        # Create a serializable analysis object
        analysis_data = {
            "timestamp": datetime.now().isoformat(),
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

        # Write to JSON file
        with open(log_file, 'a') as f:
            json.dump(data, f)
            f.write('\n')
        
        # Send to IDS server
        try:
            response = ids_client.process_log({
                "type": "REQUEST",
                "analysis_data": json.dumps(analysis_data)  # Convert to JSON string
            })
            
            logger.info(format_log_message(response, data))
            return True, response
            
        except Exception as e:
            logger.error(f"Error communicating with IDS server: {str(e)}")
            return False, ids_pb2.ProcessResult(
                injection_detected=False,
                message=f"Error processing request: {str(e)}",
                matched_rules=[]
            )
            
    except Exception as e:
        logger.error(f"Error in log_entry: {str(e)}")
        return False, ids_pb2.ProcessResult(
            injection_detected=False,
            message=f"Error processing request: {str(e)}",
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
        success, _ = log_request(request)
        
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