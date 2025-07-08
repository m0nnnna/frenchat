import threading
import queue
import os
import json
import encryption_utils as enc
from federation import Federation

class ServerBackend:
    def __init__(self, client_id, host='0.0.0.0', port=8443):
        self.client_id = client_id
        self.inbox = queue.Queue()
        self.outbox = queue.Queue()
        self.host = host
        self.port = port
        self.public_key, self.private_key = self.load_or_generate_keys()
        self.federation = Federation(client_id, host, port, self.public_key, self.private_key)
        self.federation.register_message_handler(self.handle_federated_message)
        self.federation.start()
        print(f"[SERVER] Backend started for {client_id} on {host}:{port}")

    def load_or_generate_keys(self):
        key_file = 'server_private_key.pem'
        pub_file = 'server_public_key.pem'
        if os.path.exists(key_file) and os.path.exists(pub_file):
            with open(key_file, 'rb') as f:
                private_key = enc.deserialize_private_key(f.read())
            with open(pub_file, 'rb') as f:
                public_key = enc.deserialize_public_key(f.read())
            print("[SERVER] Loaded existing server RSA keys")
        else:
            private_key, public_key = enc.generate_rsa_keypair()
            with open(key_file, 'wb') as f:
                f.write(enc.serialize_private_key(private_key))
            with open(pub_file, 'wb') as f:
                f.write(enc.serialize_public_key(public_key).encode('utf-8'))
            print("[SERVER] Generated and saved new server RSA keys")
        return public_key, private_key

    def handle_federated_message(self, msg, peer_id):
        print(f"[SERVER] handle_federated_message from {peer_id}: {msg}")
        if msg.get('type') == 'chat_message':
            self.outbox.put({
                'type': 'chat_message',
                'from_client': msg.get('from_client', peer_id),
                'from_server': peer_id,
                'message': msg.get('message')
            })
        elif msg.get('type') == 'key_approval':
            self.outbox.put({
                'type': 'key_approval',
                'server_addr': msg.get('server_addr'),
                'public_key': msg.get('public_key'),
                'reason': msg.get('reason')
            })
        elif msg.get('type') == 'add_contact':
            self.outbox.put({
                'type': 'add_contact',
                'address': msg.get('address'),
                'username': msg.get('username')
            })
        else:
            self.outbox.put(msg)

    def get_message(self, timeout=0.1):
        try:
            return self.outbox.get(timeout=timeout)
        except queue.Empty:
            return None

    def send_command(self, command, args):
        print(f"[SERVER] send_command: {command} {args}")
        if command == 'chat_message':
            parts = args.split(' ', 2)
            if len(parts) >= 2:
                target = parts[0]
                message = parts[1] if len(parts) == 2 else ' '.join(parts[1:])
                msg = {
                    'type': 'chat_message',
                    'from_client': self.client_id,
                    'message': message
                }
                if ':' in target:
                    address, port = target.split(':')
                    try:
                        port = int(port)
                        self.federation.send_message(f"{address}:{port}", port, msg)
                    except Exception as e:
                        print(f"[SERVER] send_message error: {e}")
        elif command == 'add_contact':
            parts = args.split(' ', 1)
            if len(parts) == 2:
                address, public_key_pem = parts
                self.federation.approve_key(address, public_key_pem)
                self.outbox.put({'type': 'info', 'message': f'Contact {address} added.'})
        elif command == 'approve_key':
            parts = args.split(' ', 1)
            if len(parts) == 2:
                address, public_key_pem = parts
                self.federation.approve_key(address, public_key_pem)
                self.outbox.put({'type': 'info', 'message': f'Key approved for {address}.'})
        elif command == 'contact_request':
            # Args: address:port
            address = args.strip()
            if ':' in address:
                host, port = address.split(':')
                try:
                    port = int(port)
                    self.federation.send_contact_request(address, port)
                except Exception as e:
                    print(f"[SERVER] contact_request error: {e}")
        elif command == 'approve_contact_request':
            # Args: address:port request_id
            parts = args.split(' ', 1)
            if len(parts) == 2:
                address, request_id = parts
                self.federation.approve_contact_request(address, request_id)
        elif command == 'reject_contact_request':
            # Args: address:port request_id
            parts = args.split(' ', 1)
            if len(parts) == 2:
                address, request_id = parts
                self.federation.reject_contact_request(address, request_id)
        else:
            self.outbox.put({'type': 'info', 'message': f'Unknown command: {command} {args}'})

    def get_contacts(self):
        return self.federation.get_known_contacts()

    def stop(self):
        self.federation.stop()
        print("[SERVER] Backend stopped.")

    def get_public_key(self, address):
        # Return the PEM-encoded public key for a given address, or None if not found
        key = self.federation.known_servers.get(address)
        if key:
            return enc.serialize_public_key(key)
        return None

def run_server(client_id):
    print(f"[SERVER] run_server called for client_id: {client_id}")
    # No-op for now; real server logic can be added here 