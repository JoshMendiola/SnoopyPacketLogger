import os
import json
from flask import Flask, request, Response, jsonify
import requests
from datetime import datetime
from flask_cors import CORS
from waf_client import WAFClient
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
WAF_SERVER = os.getenv('WAF_SERVER')  # Changed from IDS_SERVER
WAF_PORT = os.getenv('WAF_PORT')  # Changed from IDS_PORT

logger.info(f"Initializing WAF client with server {WAF_SERVER}:{WAF_PORT}")
waf_client = WAFClient(WAF_SERVER, WAF_PORT)  # Changed from ids_client


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

        logger.info("\n=== Sending Log to WAF Server ===")
        logger.info(f"Timestamp: {timestamp}")
        logger.info(f"IP: {data.get('ip')}")
        logger.info(f"Method: {data.get('method')}")
        logger.info(f"Path: {data.get('path')}")

    if data.get('body'):
        logger.info(f"Body Length: {len(data['body'])} characters")
        # Log first 100 characters of body for visibility
        logger.info(f"Body Preview: {data['body'][:100]}...")

    # Send log to WAF server
    attack_detected, message, should_block = waf_client.process_log(log_data)

    if attack_detected:
        logger.warning("\n🚨 ALERT: Potential Attack Detected!")
        logger.warning(f"WAF Message: {message}")
        if should_block:
            logger.warning("⛔ Request will be blocked (Prevention Mode Active)")
    else:
        logger.info("\n✅ No Attack detected")
        logger.info(f"WAF Message: {message}")

    logger.info("=" * 50)  # Separator line
    return attack_detected, message, should_block


def log_request(req):
    logger.info(f"\n>>> New Request: {req.method} {req.full_path}")
    logger.info(f"From IP: {req.remote_addr}")

    headers = dict(req.headers)
    logger.info(f"Headers: {json.dumps(headers, indent=2)}")

    body = req.get_data(as_text=True) if req.method in ['POST', 'PUT', 'PATCH'] else None
    logger.info(f"FULL PATH: {req.full_path}")
    logger.info(f"THIS IS THE BODY VARIABLE: {body}")

    log_data = {
        "type": "REQUEST",
        "ip": req.remote_addr,
        "method": req.method,
        "path": req.full_path,
        "headers": headers,
        "body": body
    }

    return log_entry(log_data)


@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def proxy(path):
    start_time = datetime.now()
    logger.info(f"\n=== New Request to {path} ===")

    try:
        attack_detected, message, should_block = log_request(request)

        if should_block:
            logger.warning("⛔ Request blocked by WAF")

            safe_message = message.encode('ascii', 'ignore').decode('ascii')

            return Response(
                "Request blocked by WAF",
                status=403,
                headers={'X-WAF-Block-Reason': safe_message}
            )

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
        logger.info("=" * 50)

        return response

    except Exception as e:
        logger.error(f"Error processing request: {str(e)}")
        logger.info("=" * 50)
        return Response("Internal Server Error", status=500)


# Add endpoint for prevention mode control
@app.route('/api/waf/prevention', methods=['GET', 'POST'])
def prevention_mode():
    try:
        if request.method == 'GET':
            enabled = waf_client.get_prevention_mode()
            return jsonify({'prevention_mode': enabled})
        else:
            data = request.get_json()
            if data is None or 'enabled' not in data:
                return jsonify({'error': 'Missing enabled parameter'}), 400

            success = waf_client.set_prevention_mode(data['enabled'])
            return jsonify({
                'prevention_mode': success,
                'status': 'updated' if success else 'failed'
            })
    except Exception as e:
        logger.error(f"Error handling prevention mode request: {str(e)}")
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    logger.info("Starting Packet Logger Service")
    logger.info(f"WAF Server: {WAF_SERVER}:{WAF_PORT}")

    # Ensure the log file exists
    if not os.path.exists(log_file):
        with open(log_file, 'w') as f:
            pass
        logger.info(f"Created log file: {log_file}")

    app.run(host='0.0.0.0', port=5000, debug=False)