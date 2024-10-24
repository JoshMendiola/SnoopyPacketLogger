import os
import json
from flask import Flask, request, Response
import requests
from datetime import datetime
from flask_cors import CORS
from ids_client import IDSClient

app = Flask(__name__)
CORS(app)

# Configure JSON logging
log_file = '/var/log/nginx/packet_logger.json'

NGINX_SERVER = "http://nginx:80"
IDS_SERVER = os.getenv('IDS_SERVER')  # Use environment variable or default to localhost
IDS_PORT = os.getenv('IDS_PORT')  # Use environment variable or default to 50051

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
        f.write('\n')  # Add a newline for readability

    # Send log to IDS server
    injection_detected, message = ids_client.process_log(log_data)
    print(f"IDS Response: {message}")
    if injection_detected:
        print("WARNING: SQL Injection attempt detected!")


def log_request(req):
    headers = dict(req.headers)
    body = req.get_data(as_text=True) if req.method in ['POST', 'PUT', 'PATCH'] else None
    log_entry({
        "type": "REQUEST",
        "ip": req.remote_addr,
        "method": req.method,
        "path": req.full_path,
        "headers": headers,
        "body": body
    })


@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def proxy(path):
    log_request(request)

    resp = requests.request(
        method=request.method,
        url=f"{NGINX_SERVER}/{path}",
        headers={key: value for (key, value) in request.headers if key != 'Host'},
        data=request.get_data(),
        cookies=request.cookies,
        allow_redirects=False)

    excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
    headers = [(name, value) for (name, value) in resp.raw.headers.items()
               if name.lower() not in excluded_headers]

    response = Response(resp.content, resp.status_code, headers)
    return response


if __name__ == '__main__':
    # Ensure the log file exists
    if not os.path.exists(log_file):
        with open(log_file, 'w') as f:
            pass  # Create an empty file
    app.run(host='0.0.0.0', port=5000, debug=False)
