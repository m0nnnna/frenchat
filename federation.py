# federation.py
"""
Federated server-to-server logic for the chat system.
Handles connection establishment, approval, key management, user list exchange, and message routing.
"""

import threading
import json
import time
import traceback
import ssl
import encryption_utils as enc
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import socket
import os
import uuid
# User directory imports removed - using simplified federation approach
# Import other dependencies from server.py as needed (to be resolved after move)
# from server import ...

class Federation:
    def __init__(self, client_id, host, port, public_key, private_key, key_store_file='known_servers.json'):
        self.client_id = client_id
        self.host = host
        self.port = port
        self.public_key = public_key
        self.private_key = private_key
        self.message_handler = None
        self.running = False
        self.key_store_file = key_store_file
        self.known_servers = self.load_known_servers()
        self.lock = threading.Lock()

    def load_known_servers(self):
        if os.path.exists(self.key_store_file):
            with open(self.key_store_file, 'r') as f:
                data = json.load(f)
            # Convert PEM strings to public key objects
            return {addr: enc.deserialize_public_key(pem) for addr, pem in data.items()}
        return {}

    def save_known_servers(self):
        with open(self.key_store_file, 'w') as f:
            # Convert public key objects to PEM strings
            data = {addr: enc.serialize_public_key(key) for addr, key in self.known_servers.items()}
            json.dump(data, f)

    def start(self):
        self.running = True
        self.listener_thread = threading.Thread(target=self.listen_loop, daemon=True)
        self.listener_thread.start()
        print(f"[FEDERATION] Listening for stateless messages on {self.host}:{self.port}")

    def stop(self):
        self.running = False
        # Create a dummy connection to unblock the listener if needed
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((self.host, self.port))
        except:
            pass
        print("[FEDERATION] Stopped.")

    def listen_loop(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((self.host, self.port))
            server_socket.listen(5)
            while self.running:
                try:
                    client_sock, addr = server_socket.accept()
                    threading.Thread(target=self.handle_incoming_message, args=(client_sock, addr), daemon=True).start()
                except Exception as e:
                    if self.running:
                        print(f"[FEDERATION] Accept error: {e}")

    def handle_incoming_message(self, sock, addr):
        try:
            data = sock.recv(65536)
            if not data:
                return
            header_len = int.from_bytes(data[:4], 'big')
            header = json.loads(data[4:4+header_len].decode('utf-8'))
            encrypted_msg = data[4+header_len:]
            sender_addr = header.get('server_addr', f"{addr[0]}:{addr[1]}")
            sender_pem = header.get('public_key')
            with self.lock:
                known_key = self.known_servers.get(sender_addr)
            sender_key = enc.deserialize_public_key(sender_pem)
            key_changed = known_key and (enc.serialize_public_key(known_key) != sender_pem)
            new_key = not known_key
            if new_key or key_changed:
                if self.message_handler:
                    event = {
                        'type': 'key_approval',
                        'server_addr': sender_addr,
                        'public_key': sender_pem,
                        'reason': 'new' if new_key else 'changed'
                    }
                    self.message_handler(event, sender_addr)
                with self.lock:
                    self.known_servers[sender_addr] = sender_key
                    self.save_known_servers()
            # Try to decrypt, but if it fails, try to parse as JSON
            try:
                decrypted = enc.rsa_decrypt(self.private_key, encrypted_msg)
                msg_data = json.loads(decrypted.decode('utf-8'))
            except Exception as e:
                try:
                    msg_data = json.loads(encrypted_msg.decode('utf-8'))
                    print(f"[FEDERATION] Received unencrypted message from {sender_addr}: {msg_data}")
                except Exception as e2:
                    print(f"[FEDERATION] Decrypt and JSON parse error from {sender_addr}: {e} / {e2}")
                    return
            print(f"[FEDERATION] Received from {sender_addr}: {msg_data}")
            # Handle contact request/response
            if msg_data.get('type') == 'contact_request':
                self.handle_contact_request(msg_data, sender_addr)
            elif msg_data.get('type') == 'contact_response':
                self.handle_contact_response(msg_data, sender_addr)
            else:
                if self.message_handler:
                    self.message_handler(msg_data, sender_addr)
        except Exception as e:
            print(f"[FEDERATION] Incoming message error: {e}")
        finally:
            sock.close()

    def send_message(self, address, port, message, peer_key=None):
        # peer_key is optional; if not provided, use known_servers
        with self.lock:
            if peer_key is None:
                peer_key = self.known_servers.get(address)
        if not peer_key:
            print(f"[FEDERATION] No known public key for {address}. Cannot send message.")
            return False
        try:
            header = {
                'server_addr': f"{self.host}:{self.port}",
                'public_key': enc.serialize_public_key(self.public_key)
            }
            header_bytes = json.dumps(header).encode('utf-8')
            header_len = len(header_bytes).to_bytes(4, 'big')
            encrypted = enc.rsa_encrypt(peer_key, json.dumps(message).encode('utf-8'))
            payload = header_len + header_bytes + encrypted
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((address.split(':')[0], int(port)))
                s.sendall(payload)
            print(f"[FEDERATION] Sent stateless message to {address}:{port}: {message}")
            return True
        except Exception as e:
            print(f"[FEDERATION] Send error to {address}:{port}: {e}")
            return False

    def send_contact_request(self, address, port):
        request_id = str(uuid.uuid4())
        msg = {
            'type': 'contact_request',
            'request_id': request_id,
            'from_addr': f"{self.host}:{self.port}",
            'from_username': self.client_id,
            'public_key': enc.serialize_public_key(self.public_key)
        }
        try:
            header = {
                'server_addr': f"{self.host}:{self.port}",
                'public_key': enc.serialize_public_key(self.public_key)
            }
            header_bytes = json.dumps(header).encode('utf-8')
            header_len = len(header_bytes).to_bytes(4, 'big')
            payload = header_len + header_bytes + json.dumps(msg).encode('utf-8')
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((address.split(':')[0], int(port)))
                s.sendall(payload)
            print(f"[FEDERATION] Sent contact request to {address}:{port}")
            return request_id
        except Exception as e:
            print(f"[FEDERATION] Contact request error to {address}:{port}: {e}")
            return None

    def handle_contact_request(self, msg, sender_addr):
        # Always save the sender's public key so we can send messages back after approval
        public_key_pem = msg.get('public_key')
        if public_key_pem:
            with self.lock:
                self.known_servers[sender_addr] = enc.deserialize_public_key(public_key_pem)
                self.save_known_servers()
            print(f"[FEDERATION] Saved public key for {sender_addr} from contact request.")
        if self.message_handler:
            event = {
                'type': 'contact_request',
                'from_addr': sender_addr,
                'from_username': msg.get('from_username', sender_addr),
                'request_id': msg.get('request_id'),
                'public_key': public_key_pem
            }
            self.message_handler(event, sender_addr)

    def handle_contact_response(self, msg, sender_addr):
        status = msg.get('status')
        request_id = msg.get('request_id')
        responder_username = msg.get('username', sender_addr)
        if status == 'approved':
            public_key_pem = msg.get('public_key')
            with self.lock:
                self.known_servers[sender_addr] = enc.deserialize_public_key(public_key_pem)
                self.save_known_servers()
            # Add responder to contacts (with username) and trust the key immediately
            if self.message_handler:
                self.message_handler({'type': 'info', 'message': f'Contact {responder_username} ({sender_addr}) approved and added.'}, sender_addr)
                self.message_handler({'type': 'add_contact', 'address': sender_addr, 'username': responder_username}, sender_addr)
            # Also, immediately approve the key for this contact (no key_approval event needed)
            # This ensures the GUI/backend will not prompt for key approval for this contact
        else:
            if self.message_handler:
                self.message_handler({'type': 'info', 'message': f'Contact request to {sender_addr} was rejected.'}, sender_addr)

    def approve_contact_request(self, sender_addr, request_id, from_username=None):
        # Always process approval and send automated message, even if already in contacts
        msg = {
            'type': 'contact_response',
            'request_id': request_id,
            'status': 'approved',
            'public_key': enc.serialize_public_key(self.public_key),
            'username': self.client_id
        }
        with self.lock:
            if sender_addr not in self.known_servers:
                print(f"[FEDERATION] Warning: approving contact for unknown key {sender_addr}")
        # Send approval response (always)
        sent_response = self.send_message(sender_addr, sender_addr.split(':')[1], msg, peer_key=self.known_servers.get(sender_addr))
        print(f"[FEDERATION] Sent contact approval response to {sender_addr}: {sent_response}")
        # Always notify the GUI/backend to add the requester as a contact, using from_username if available
        requester_username = from_username or sender_addr
        if self.message_handler:
            self.message_handler({'type': 'add_contact', 'address': sender_addr, 'username': requester_username}, sender_addr)
        # Always send an automated chat message to notify the requester, even if already in contacts
        with self.lock:
            peer_key = self.known_servers.get(sender_addr)
        if peer_key:
            auto_msg = {
                'type': 'chat_message',
                'from_client': self.client_id,
                'message': f'{self.client_id} has accepted your chat request.'
            }
            sent_auto = self.send_message(sender_addr, sender_addr.split(':')[1], auto_msg, peer_key=peer_key)
            print(f"[FEDERATION] Sent automated acceptance message to {sender_addr}: {sent_auto}")
        else:
            print(f"[FEDERATION] Cannot send automated message to {sender_addr}: no known public key.")
        # Do NOT send a contact request back or auto-approve on A
        # This logic guarantees the requester always gets a chat message after approval, triggering their key approval popup.

    def is_contact(self, address):
        # Helper to check if address is in contacts (for mutual add)
        # This can be improved to check persistent contacts if needed
        # For now, just check known_servers
        with self.lock:
            return address in self.known_servers

    def reject_contact_request(self, sender_addr, request_id):
        msg = {
            'type': 'contact_response',
            'request_id': request_id,
            'status': 'rejected'
        }
        peer_key = self.known_servers.get(sender_addr)
        self.send_message(sender_addr, sender_addr.split(':')[1], msg, peer_key=peer_key)

    def register_message_handler(self, handler):
        self.message_handler = handler

    def approve_key(self, server_addr, public_key_pem):
        # Called by backend/GUI to approve a new/changed key
        with self.lock:
            self.known_servers[server_addr] = enc.deserialize_public_key(public_key_pem)
            self.save_known_servers()
        print(f"[FEDERATION] Approved key for {server_addr}")

    def get_known_contacts(self):
        # Returns a list of known server addresses
        with self.lock:
            return list(self.known_servers.keys())

def connect_to_federated_server(server_host, server_port, server_id):
    # Placeholder: import dependencies at the top after move
    from server import FEDERATED_SERVERS, SERVER_KEYS, LOCAL_CLIENT_ID, CLIENT_SOCKETS, CLIENT_KEYS, public_pem, HOST, PORT, INPROCESS_BACKENDS, handle_federated_server, send_to_federated_server
    try:
        if server_id == LOCAL_CLIENT_ID:
            print(f"[federation] Not connecting to ourselves: {server_id}")
            return False
        if server_id in FEDERATED_SERVERS:
            print(f"[federation] Already connected to federated server {server_id}")
            return True
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.settimeout(10)
        server_socket = context.wrap_socket(server_socket, server_hostname=server_host)
        server_socket.setblocking(True)
        server_socket.connect((server_host, server_port))
        server_socket.setblocking(True)
        server_info = {
            'type': 'server_connect',
            'server_id': LOCAL_CLIENT_ID,
            'public_key': public_pem
        }
        server_socket.send(json.dumps(server_info).encode('utf-8'))
        response = server_socket.recv(4096).decode('utf-8')
        print(f"[federation] Received response from {server_id}: '{response}' (length: {len(response)})")
        if not response.strip():
            print(f"[federation] Empty response from {server_id}")
            server_socket.close()
            return False
        response_data = json.loads(response)
        if response_data.get('status') == 'accepted':
            server_public_key = enc.deserialize_public_key(response_data['public_key'])
            FEDERATED_SERVERS[server_id] = server_socket
            SERVER_KEYS[server_id] = server_public_key
            print(f"[federation] Connected to federated server {server_id} at {server_host}:{server_port}")
            threading.Thread(target=handle_federated_server, args=(server_socket, server_id), daemon=True).start()
            time.sleep(0.1)
            # No user list exchange - just notify backends of connection
            for backend in INPROCESS_BACKENDS.values():
                backend.receive_federated_message({
                    'status': 'server_connected',
                    'server_id': server_id,
                    'host': server_host,
                    'port': server_port
                })
            print(f"[federation] Successfully connected to federated server {server_id}")
            return True
        else:
            print(f"[federation] Failed to connect to federated server {server_id}: {response_data.get('message', 'Unknown error')}")
            server_socket.close()
            return False
    except Exception as e:
        print(f"[federation] Error connecting to federated server {server_id}: {e}")
        return False

def handle_server_connection(server_socket, server_info, address):
    try:
        from server import FEDERATED_SERVERS, SERVER_KEYS, LOCAL_CLIENT_ID, CLIENT_SOCKETS, CLIENT_KEYS, public_pem, HOST, PORT, INPROCESS_BACKENDS, send_to_client
        import time
        server_id = server_info['server_id']
        server_public_key_pem = server_info['public_key']
        server_public_key = enc.deserialize_public_key(server_public_key_pem)

        # Always require approval for every incoming connection
        for backend in INPROCESS_BACKENDS.values():
            backend.receive_federated_message({
                'type': 'federated_connection_request',
                'server_id': server_id,
                'server_address': f"{address[0]}:{address[1]}"
            })

        # Wait for approval or rejection (simple polling, can be improved)
        approved = False
        if not hasattr(handle_server_connection, 'pending_approvals'):
            handle_server_connection.pending_approvals = {}
        for _ in range(100):  # Wait up to ~10 seconds
            if server_id in handle_server_connection.pending_approvals:
                approved = handle_server_connection.pending_approvals.pop(server_id)
                break
            time.sleep(0.1)
        if not approved:
            print(f"[federation] Connection from {server_id} rejected or timed out.")
            server_socket.close()
            return

        # Accept connection
        response = {
            'status': 'accepted',
            'public_key': public_pem
        }
        response_json = json.dumps(response)
        print(f"[federation] Sending response to {server_id}: {response_json}")
        server_socket.send(response_json.encode('utf-8'))
        print(f"[federation] Response sent to {server_id}")

        # Reject duplicate connections
        if server_id in FEDERATED_SERVERS:
            print(f"[federation] Already connected to federated server {server_id}, rejecting duplicate connection.")
            server_socket.close()
            return

        FEDERATED_SERVERS[server_id] = server_socket
        SERVER_KEYS[server_id] = server_public_key
        print(f"[federation] Federated server {server_id} connected from {address}")

        # No user list exchange - just notify backends
        for backend in INPROCESS_BACKENDS.values():
            backend.receive_federated_message({
                'status': 'server_connected',
                'server_id': server_id,
                'host': address[0],
                'port': address[1]
            })

        print(f"[federation] Starting federated server message handler thread for {server_id}")
        federated_thread = threading.Thread(
            target=handle_federated_server,
            args=(server_socket, server_id),
            daemon=True
        )
        federated_thread.start()
        print(f"[federation] Federated server message handler thread started for {server_id}")

        # No user list exchange needed
    except Exception as e:
        print(f"[federation] Error handling server connection from {address}: {e}")
        traceback.print_exc()
        server_socket.close()

def approve_federated_connection(server_id):
    from server import handle_server_connection, FEDERATED_SERVERS, SERVER_KEYS, LOCAL_CLIENT_ID, CLIENT_SOCKETS, CLIENT_KEYS, public_pem, HOST, PORT, INPROCESS_BACKENDS, send_to_federated_server
    if hasattr(handle_server_connection, 'pending_connections') and server_id in handle_server_connection.pending_connections:
        connection_request = handle_server_connection.pending_connections[server_id]
        server_socket = connection_request['socket']
        server_info = connection_request['server_info']
        server_public_key_pem = connection_request['public_key']
        server_public_key = enc.deserialize_public_key(server_public_key_pem)
        response = {
            'status': 'accepted',
            'public_key': public_pem
        }
        server_socket.send(json.dumps(response).encode('utf-8'))
        FEDERATED_SERVERS[server_id] = server_socket
        SERVER_KEYS[server_id] = server_public_key
        del handle_server_connection.pending_connections[server_id]
        print(f"[federation] User approved connection from federated server {server_id}")
        for backend in INPROCESS_BACKENDS.values():
            backend.receive_federated_message({
                'status': 'server_connected',
                'server_id': server_id,
                'host': connection_request['server_address'].split(':')[0],
                'port': int(connection_request['server_address'].split(':')[1])
            })
        print(f"[federation] Starting federated server message handler thread for {server_id}")
        federated_thread = threading.Thread(
            target=handle_federated_server,
            args=(server_socket, server_id),
            daemon=True
        )
        federated_thread.start()
        return True
    return False

def reject_federated_connection(server_id):
    from server import handle_server_connection
    if hasattr(handle_server_connection, 'pending_connections') and server_id in handle_server_connection.pending_connections:
        connection_request = handle_server_connection.pending_connections[server_id]
        server_socket = connection_request['socket']
        response = {
            'status': 'rejected',
            'message': 'Connection rejected by user'
        }
        server_socket.send(json.dumps(response).encode('utf-8'))
        server_socket.close()
        del handle_server_connection.pending_connections[server_id]
        print(f"[federation] User rejected connection from federated server {server_id}")
        return True
    return False

def handle_federated_server(server_socket, server_id):
    from server import FEDERATED_SERVERS, handle_federated_message, private_key
    import traceback
    try:
        try:
            print(f"[DEBUG] handle_federated_server starting for {server_id}")
            server_socket.setblocking(True)
            server_socket.settimeout(300)
        except OSError as e:
            print(f"[federation] Socket already closed for {server_id}: {e}")
            return
        last_ping = time.time()
        while True:
            try:
                current_time = time.time()
                if current_time - last_ping > 60:
                    from server import LOCAL_CLIENT_ID
                    ping_msg = {
                        'type': 'ping',
                        'from_server': LOCAL_CLIENT_ID,
                        'timestamp': current_time
                    }
                    encrypted_ping = enc.rsa_encrypt(private_key.public_key(), json.dumps(ping_msg).encode('utf-8'))
                    print(f"[DEBUG] Sending keepalive ping to {server_id}")
                    server_socket.send(encrypted_ping)
                    print(f"[federation] Sent keepalive ping to federated server {server_id}")
                    last_ping = current_time
                print(f"[DEBUG] Waiting to receive message from {server_id}")
                raw_msg = server_socket.recv(4096)
                print(f"[DEBUG] Received {len(raw_msg) if raw_msg else 0} bytes from {server_id}")
                if not raw_msg:
                    print(f"[DEBUG] Socket closed by peer {server_id}")
                    break
                print(f"[federation] Received message from federated server {server_id}: {len(raw_msg)} bytes")
                # Try plaintext first
                try:
                    decoded = raw_msg.decode('utf-8')
                    msg_data = json.loads(decoded)
                    print(f"[federation] PLAINTEXT message from {server_id}: {msg_data.get('type', 'unknown')}")
                    handle_federated_message(msg_data, server_id)
                    continue
                except Exception:
                    pass  # Not plaintext, try encrypted
                # Try encrypted
                try:
                    decrypted_msg = enc.rsa_decrypt(private_key, raw_msg)
                    msg_data = json.loads(decrypted_msg.decode('utf-8'))
                    print(f"[federation] Decrypted message from {server_id}: {msg_data.get('type', 'unknown')}")
                    handle_federated_message(msg_data, server_id)
                except Exception as e:
                    print(f"[federation] Error decrypting/handling message from {server_id}: {e}")
                    traceback.print_exc()
            except Exception as e:
                print(f"[federation] Error in federated server handler for {server_id}: {e}")
                traceback.print_exc()
                break
    finally:
        print(f"[DEBUG] handle_federated_server finally block for {server_id}")
        if server_id in FEDERATED_SERVERS:
            del FEDERATED_SERVERS[server_id]
        from server import SERVER_KEYS
        if server_id in SERVER_KEYS:
            del SERVER_KEYS[server_id]
        try:
            print(f"[DEBUG] Closing socket for {server_id}")
            server_socket.close()
        except Exception as e:
            print(f"[DEBUG] Exception closing socket for {server_id}: {e}")
        print(f"[federation] Disconnected from federated server {server_id}")
        print(f"[DEBUG] handle_federated_server thread exiting for {server_id}")

def send_to_federated_server(server_id, message):
    from server import FEDERATED_SERVERS, SERVER_KEYS
    if server_id in FEDERATED_SERVERS:
        try:
            server_socket = FEDERATED_SERVERS[server_id]
            msg_type = message.get('type')
            # Send user list messages in plaintext
            if msg_type in ('get_users', 'user_list_response'):
                message_json = json.dumps(message)
                print(f"[federation] Sending PLAINTEXT message for {server_id}: {msg_type}")
                server_socket.send(message_json.encode('utf-8'))
                print(f"[federation] Successfully sent PLAINTEXT message to federated server {server_id}: {msg_type}")
                return True
            # All other messages remain encrypted
            server_public_key = SERVER_KEYS.get(server_id)
            print(f"[federation] SERVER_KEYS for {server_id}: {server_public_key} (type: {type(server_public_key)})")
            if not server_public_key:
                print(f"[federation] No public key for federated server {server_id} in SERVER_KEYS: {SERVER_KEYS.keys()}")
                return False
            if not hasattr(server_public_key, 'encrypt'):
                print(f"[federation] Public key for {server_id} is not a valid public key object: {server_public_key}")
                return False
            message_json = json.dumps(message)
            print(f"[federation] Encrypting message for {server_id}: {msg_type}")
            encrypted_msg = enc.rsa_encrypt(server_public_key, message_json.encode('utf-8'))
            server_socket.send(encrypted_msg)
            print(f"[federation] Successfully sent message to federated server {server_id}: {msg_type}")
            return True
        except (ValueError, ssl.SSLEOFError, ssl.SSLError, ConnectionResetError, BrokenPipeError) as e:
            print(f"[federation] Connection error with federated server {server_id}: {e}")
            if server_id in FEDERATED_SERVERS:
                try:
                    FEDERATED_SERVERS[server_id].close()
                except:
                    pass
                del FEDERATED_SERVERS[server_id]
                print(f"[federation] Removed failed federated server {server_id}")
            return False
        except Exception as e:
            print(f"[federation] Error sending to federated server {server_id}: {e}")
            return False
    else:
        print(f"[federation] Federated server {server_id} not found in FEDERATED_SERVERS")
        return False

# Add any additional helpers/constants as needed 