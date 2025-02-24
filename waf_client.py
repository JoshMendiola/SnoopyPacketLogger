import grpc
import waf_pb2
import waf_pb2_grpc
import socket
import time


class WAFClient:
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
                    ('grpc.keepalive_time_ms', 30000),
                    ('grpc.keepalive_timeout_ms', 10000),
                    ('grpc.keepalive_permit_without_calls', False),
                    ('grpc.http2.max_pings_without_data', 2),
                    ('grpc.http2.min_time_between_pings_ms', 30000),
                    ('grpc.http2.min_ping_interval_without_data_ms', 30000),
                    ('grpc.max_receive_message_length', 1024 * 1024 * 100),  # 100MB
                    ('grpc.max_send_message_length', 1024 * 1024 * 100),  # 100MB
                ]

                target = f"{host}:{port}"
                print(f"Attempting to connect to WAF server at {target} (Attempt {attempt + 1}/{max_retries})")

                self.channel = grpc.secure_channel(target, credentials, options=options)

                # Add channel connectivity callback
                self.channel.subscribe(self._on_channel_state_change)

                self.stub = waf_pb2_grpc.WAFStub(self.channel)
                self.client_id = f"packet_logger_{socket.gethostname()}"

                # Verify connection with a shorter timeout
                grpc.channel_ready_future(self.channel).result(timeout=5)

                if self.check_server_health():
                    print(f"Successfully connected to WAF server at {target}")
                    return

            except grpc.FutureTimeoutError:
                print(f"Timeout while connecting to WAF server (Attempt {attempt + 1})")
            except Exception as e:
                print(f"Failed to connect to WAF server: {str(e)} (Attempt {attempt + 1})")

            if attempt < max_retries - 1:
                print(f"Retrying in {retry_delay} seconds...")
                time.sleep(retry_delay)

        raise Exception("Failed to connect to WAF server after multiple attempts")

    def _on_channel_state_change(self, connectivity):
        """Monitor channel state changes"""
        print(f"Channel connectivity changed to: {connectivity}")
        if connectivity == grpc.ChannelConnectivity.TRANSIENT_FAILURE:
            print("Channel experienced transient failure, will automatically reconnect")
        elif connectivity == grpc.ChannelConnectivity.SHUTDOWN:
            print("Channel has been shutdown")

    def check_server_health(self):
        try:
            request = waf_pb2.HealthCheckRequest(client_id=self.client_id)
            response = self.stub.HealthCheck(request)
            if response.is_healthy:
                print("Successfully connected to WAF server")
            return response.is_healthy
        except grpc.RpcError as e:
            print(f"Health check failed: {e}")
            return False

    def process_log(self, log_entry):
        # Add retry logic for processing logs
        max_retries = 3
        retry_delay = 1

        for attempt in range(max_retries):
            try:
                # Create the log entry request
                request = waf_pb2.LogEntry(
                    timestamp=log_entry['timestamp'],
                    type=log_entry['type'],
                    ip=log_entry['ip'],
                    method=log_entry['method'],
                    path=log_entry['path'],
                    headers={k: str(v) for k, v in log_entry['headers'].items()},
                    body=log_entry.get('body', ''),
                    client_id=self.client_id
                )

                # Send the log to the WAF server
                print("\nSending request to WAF server...")
                response = self.stub.ProcessLog(request)
                print("Response received from WAF server")

                if response.injection_detected:
                    print("\n🚨 ALERT: Potential Injection Detected!")
                    if response.matched_rules:
                        print(f"Matched Rules: {', '.join(response.matched_rules)}")
                    print(f"Server Message: {response.message}")
                    if response.should_block:
                        print("⛔ Request will be blocked (Prevention Mode Active)")
                else:
                    print("\n✅ No injection detected")
                    print(f"Server Message: {response.message}")

                return response.injection_detected, response.message, response.should_block

            except grpc.RpcError as e:
                print(f"\n❌ RPC Error on attempt {attempt + 1}:")
                print(f"Error details: {e}")
                if attempt < max_retries - 1:
                    print(f"Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                else:
                    error_message = f"Failed to communicate with WAF after {max_retries} attempts"
                    print(f"\n❌ {error_message}")
                    return False, error_message, False

    def get_prevention_mode(self):
        """Get the current prevention mode status"""
        try:
            request = waf_pb2.PreventionModeRequest(client_id=self.client_id)
            response = self.stub.GetPreventionMode(request)
            return response.enabled
        except grpc.RpcError as e:
            print(f"Error getting prevention mode: {e}")
            return False

    def set_prevention_mode(self, enabled):
        """Set the prevention mode status"""
        try:
            request = waf_pb2.SetPreventionModeRequest(
                client_id=self.client_id,
                enabled=enabled
            )
            response = self.stub.SetPreventionMode(request)
            status = "enabled" if response.enabled else "disabled"
            print(f"Prevention mode {status}")
            return response.enabled
        except grpc.RpcError as e:
            print(f"Error setting prevention mode: {e}")
            return False

    def close(self):
        self.channel.close()