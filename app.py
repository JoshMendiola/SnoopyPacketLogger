import os
import json
from flask import Flask, request, Response
import requests
from datetime import datetime
from flask_socketio import SocketIO
from flask_cors import CORS

app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Configure JSON logging
log_file = '/var/log/nginx/packet_logger.json'

NGINX_SERVER = "http://nginx:80"


def log_entry(entry_type, data):
    timestamp = datetime.now().isoformat()
    log_data = {
        "timestamp": timestamp,
        "type": entry_type,
        **data
    }

    # Write the log entry to the JSON file
    with open(log_file, 'a') as f:
        json.dump(log_data, f)
        f.write('\n')  # Add a newline for readability

    # Emit the log message to any connected WebSocket clients
    try:
        socketio.emit('log', json.dumps(log_data))
        print(f"WebSocket event emitted: {json.dumps(log_data)}")  # Debug print statement to confirm emission
    except Exception as e:
        print(f"Failed to emit WebSocket event: {e}")  # Print error if emission fails


def log_request(req):
    headers = dict(req.headers)
    body = req.get_data(as_text=True) if req.method in ['POST', 'PUT', 'PATCH'] else None
    log_entry("REQUEST", {
        "ip": req.remote_addr,
        "method": req.method,
        "path": req.full_path,
        "headers": headers,
        "body": body
    })


def log_response(resp):
    headers = dict(resp.headers)
    content_type = headers.get('Content-Type', '')
    body = None
    if 'text/html' not in content_type:
        body = resp.text[:1000] if len(resp.text) > 1000 else resp.text
    log_entry("RESPONSE", {
        "status_code": resp.status_code,
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

    log_response(resp)

    excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
    headers = [(name, value) for (name, value) in resp.raw.headers.items()
               if name.lower() not in excluded_headers]

    response = Response(resp.content, resp.status_code, headers)
    return response


@socketio.on('connect')
def handle_connect():
    print('WebSocket client connected LOGGER')


@socketio.on('disconnect')
def handle_disconnect():
    print('WebSocket client disconnected LOGGER')


if __name__ == '__main__':
    # Ensure the log file exists and is a valid JSON array
    if not os.path.exists(log_file):
        with open(log_file, 'w') as f:
            f.write('[]')
    socketio.run(app, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True, debug=False)