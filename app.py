import os
import json
from flask import Flask, request, Response
import requests
from datetime import datetime
from logging.handlers import RotatingFileHandler
import logging
from flask_socketio import SocketIO

app = Flask(__name__)

# Initialize SocketIO
socketio = SocketIO(app)

# Configure logging with rotation
log_file = '/var/log/nginx/packet_logger.log'
log_handler = RotatingFileHandler(log_file, maxBytes=10 * 1024 * 1024, backupCount=5)
log_handler.setLevel(logging.INFO)
app.logger.addHandler(log_handler)
app.logger.setLevel(logging.INFO)


NGINX_SERVER = "http://nginx:80"


def log_entry(entry_type, data):
    timestamp = datetime.now().isoformat()
    log_data = {
        "timestamp": timestamp,
        "type": entry_type,
        **data
    }
    log_message = json.dumps(log_data)
    app.logger.info(log_message)

    # Emit the log message to any connected WebSocket clients
    socketio.emit('log', log_message)


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

# WebSocket handler (optional)
@socketio.on('connect')
def handle_connect():
    print('WebSocket client connected LOGGER')

@socketio.on('disconnect')
def handle_disconnect():
    print('WebSocket client disconnected LOGGER')


if __name__ == '__main__':
    app.logger.info("App started and logging is active")
    app.run(host='0.0.0.0', port=5000)
    socketio.run(app, host='0.0.0.0', port=5000)
