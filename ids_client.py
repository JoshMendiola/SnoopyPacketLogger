# ids_client.py (Packet Logger Client)
import grpc
import ids_pb2
import ids_pb2_grpc
import socket

class IDSClient:
    def __init__(self, host, port):
        # Load certificates
        with open('ssl/ca.crt', 'rb') as f:
            root_certificates = f.read()
        with open('ssl/client.key', 'rb') as f:
            private_key = f.read()
        with open('ssl/client.crt', 'rb') as f:
            certificate_chain = f.read()
            
        # Create credentials
        credentials = grpc.ssl_channel_credentials(
            root_certificates=root_certificates,
            private_key=private_key,
            certificate_chain=certificate_chain
        )
        
        # Create secure channel
        self.channel = grpc.secure_channel(f"{host}:{port}", credentials)
        self.stub = ids_pb2_grpc.IDSStub(self.channel)
        
        # Generate a unique client ID using hostname
        self.client_id = f"packet_logger_{socket.gethostname()}"
        
        # Check server health on startup
        self.check_server_health()

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