import grpc
import ids_pb2
import ids_pb2_grpc

class IDSClient:
    def __init__(self, host, port):
        with open('ca.crt', 'rb') as f:
            root_certificates = f.read()
        with open('client.key', 'rb') as f:
            private_key = f.read()
        with open('client.crt', 'rb') as f:
            certificate_chain = f.read()

        credentials = grpc.ssl_channel_credentials(
            root_certificates=root_certificates,
            private_key=private_key,
            certificate_chain=certificate_chain
        )
        self.channel = grpc.secure_channel(f"{host}:{port}", credentials)
        self.stub = ids_pb2_grpc.IDSStub(self.channel)

    def process_log(self, log_entry):
        request = ids_pb2.LogEntry(
            timestamp=log_entry['timestamp'],
            type=log_entry['type'],
            ip=log_entry['ip'],
            method=log_entry['method'],
            path=log_entry['path'],
            headers={k: str(v) for k, v in log_entry['headers'].items()},
            body=log_entry.get('body', '')
        )
        try:
            response = self.stub.ProcessLog(request)
            return response.injection_detected, response.message
        except grpc.RpcError as e:
            print(f"gRPC error: {e}")
            return False, f"Error communicating with IDS: {e}"

    def close(self):
        self.channel.close()