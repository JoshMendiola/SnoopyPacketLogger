import os
from flask import Flask, request, Response
import requests
import logging
from datetime import datetime

app = Flask(__name__)

# Configure logging
logging.basicConfig(filename='/var/log/nginx/packet_logger.log', level=logging.INFO,
                    format='%(message)s')

NGINX_SERVER = "http://nginx:80"


def log_request(req):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    client_ip = req.remote_addr
    method = req.method
    path = req.full_path
    headers = dict(req.headers)
    body = req.get_data(as_text=True)

    log_entry = f"{timestamp} - REQUEST - IP: {client_ip}, Method: {method}, Path: {path}, Headers: {headers}, Body: {body}"
    logging.info(log_entry)


def log_response(resp):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    status_code = resp.status_code
    headers = dict(resp.headers)
    body = resp.text

    log_entry = f"{timestamp} - RESPONSE - Status: {status_code}, Headers: {headers}, Body: {body}"
    logging.info(log_entry)


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


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
