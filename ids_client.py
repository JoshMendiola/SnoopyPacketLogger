# ids_client.py (Packet Logger Client)
import grpc
import ids_pb2
import ids_pb2_grpc
import socket
import time


class IDSClient:
    def __init__(self, host, port):
        # Add connection retry logic
        max_retries = 5
        retry_delay = 2  # seconds
        
        for attempt in range(max_retries):
            try:
                # Load certificates with proper error handling
                cert_path = 'ssl'
                with open(f'{cert_path}/ca.crt', 'rb') as f:
                    root_certificates = f.read()
                with open(f'{cert_path}/client.key', 'rb') as f:
                    private_key = f.read()
                with open(f'{cert_path}/client.crt', 'rb') as f:
                    certificate_chain = f.read()
                
                # Create credentials
                credentials = grpc.ssl_channel_credentials(
                    root_certificates=root_certificates,
                    private_key=private_key,
                    certificate_chain=certificate_chain
                )
                
                # Add channel options for better connection handling
                options = [
                    ('grpc.keepalive_time_ms', 10000),
                    ('grpc.keepalive_timeout_ms', 5000),
                    ('grpc.keepalive_permit_without_calls', True),
                    ('grpc.http2.max_pings_without_data', 0),
                    ('grpc.http2.min_time_between_pings_ms', 10000),
                    ('grpc.http2.min_ping_interval_without_data_ms', 5000)
                ]
                
                target = f"{host}:{port}"
                print(f"Attempting to connect to IDS server at {target} (Attempt {attempt + 1}/{max_retries})")
                
                self.channel = grpc.secure_channel(target, credentials, options=options)
                self.stub = ids_pb2_grpc.IDSStub(self.channel)
                self.client_id = f"packet_logger_{socket.gethostname()}"
                
                # Verify connection with a shorter timeout
                grpc.channel_ready_future(self.channel).result(timeout=5)
                
                if self.check_server_health():
                    print(f"Successfully connected to IDS server at {target}")
                    return
                    
            except grpc.FutureTimeoutError:
                print(f"Timeout while connecting to IDS server (Attempt {attempt + 1})")
            except Exception as e:
                print(f"Failed to connect to IDS server: {str(e)} (Attempt {attempt + 1})")
            
            if attempt < max_retries - 1:
                print(f"Retrying in {retry_delay} seconds...")
                time.sleep(retry_delay)
        
        raise Exception("Failed to connect to IDS server after multiple attempts")

    def check_server_health(self):
        try:
            request = ids_pb2.HealthCheckRequest(client_id=self.client_id)
            response = self.stub.HealthCheck(request)
            if response.is_healthy:
                print("Successfully connected to IDS server")
            return response.is_healthy
        except grpc.RpcError as e:
            print(f"Health check failed: {e}")
            return False

    def process_log(self, log_entry):
        # Create the log entry request
        request = ids_pb2.LogEntry(
            timestamp=log_entry['timestamp'],
            type=log_entry['type'],
            ip=log_entry['ip'],
            method=log_entry['method'],
            path=log_entry['path'],
            headers={k: str(v) for k, v in log_entry['headers'].items()},
            body=log_entry.get('body', ''),
            client_id=self.client_id  # Add client ID to the request
        )

        try:
            # Send the log to the IDS server
            response = self.stub.ProcessLog(request)
            
            # Check for matched rules
            if response.injection_detected:
                rules_message = f"Matched rules: {', '.join(response.matched_rules)}" if response.matched_rules else "No specific rules matched"
                print(f"Injection detected! {rules_message}")
            
            return response.injection_detected, response.message
            
        except grpc.RpcError as e:
            error_message = f"Error communicating with IDS: {e}"
            print(error_message)
            return False, error_message

    def close(self):
        self.channel.close()