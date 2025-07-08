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
# User directory imports removed - using simplified federation approach
# Import other dependencies from server.py as needed (to be resolved after move)
# from server import ...

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
        server_id = server_info['server_id']
        server_public_key_pem = server_info['public_key']
        server_public_key = enc.deserialize_public_key(server_public_key_pem)
        
        # Always accept incoming server connections immediately
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