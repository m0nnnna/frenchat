import socket
import ssl
import threading
import json
import configparser
import os
import time
import datetime
from OpenSSL import crypto
import queue
import traceback
import random
from federation import (
    connect_to_federated_server,
    handle_server_connection,
    approve_federated_connection,
    reject_federated_connection,
    handle_federated_server,
    send_to_federated_server
)
import encryption_utils as enc
from cryptography.hazmat.primitives import serialization

# Read configuration
config = configparser.ConfigParser()
if not config.read('config.conf'):
    raise Exception("config.conf not found or invalid")
HOST = config['Network']['host']
PORT = int(config['Network']['port'])

def generate_gemstone_username():
    gemstones = [
        "Amethyst", "Aquamarine", "Citrine", "Diamond", "Emerald", "Garnet", "Jade", "Jasper", "Lapis", "Malachite",
        "Moonstone", "Obsidian", "Onyx", "Opal", "Pearl", "Peridot", "Quartz", "Ruby", "Sapphire", "Topaz", "Tourmaline", "Turquoise"
    ]
    return random.choice(gemstones) + str(random.randint(1000, 9999))

try:
    CLIENT_ID = config['Network']['client_id']
    print(f"[DEBUG] Using client_id from config: {CLIENT_ID}")
except KeyError:
    CLIENT_ID = generate_gemstone_username()
    print(f"[DEBUG] No client_id in config; using auto-generated username: {CLIENT_ID}")
CERT_FILE = 'server.crt'
KEY_FILE = 'server.key'

# Global state
CLIENT_KEYS = {}  # Store client public keys by client_id
CLIENT_SOCKETS = {}  # Store active client sockets by client_id
PENDING_CONNECTIONS = {}  # Store pending connection requests
PENDING_FILES = {}  # Store pending file transfers
CHAT_SESSIONS = {}  # Store active chat sessions

# Federated server connections
FEDERATED_SERVERS = {}  # Store connections to other servers
SERVER_KEYS = {}  # Store public keys of other servers
LOCAL_CLIENT_ID = CLIENT_ID  # This server's client ID

# Load or generate server RSA key pair
PRIVATE_KEY_FILE = 'server_private_key.pem'
PUBLIC_KEY_FILE = 'server_public_key.pem'

# At the top, add a global registry for in-process backends
INPROCESS_BACKENDS = {}

# Gemstone list for username generation
GEMSTONES = [
    "Ruby", "Sapphire", "Emerald", "Diamond", "Amethyst", "Topaz", "Garnet", "Opal",
    "Pearl", "Jade", "Turquoise", "Aquamarine", "Citrine", "Onyx", "Quartz", "Zircon",
    "Peridot", "Tanzanite", "Alexandrite", "Moonstone", "Sunstone", "Labradorite",
    "Malachite", "Lapis", "Obsidian", "Agate", "Jasper", "Carnelian", "Chalcedony"
]

# Global credential storage
CHAT_HISTORY = {}  # (user1, user2) -> encrypted_messages
ROOM_HISTORY = {}  # room_name -> encrypted_messages
ENCRYPTION_KEY = enc.generate_fernet_key()
CIPHER = enc.get_fernet(ENCRYPTION_KEY)

if os.path.exists(PRIVATE_KEY_FILE) and os.path.exists(PUBLIC_KEY_FILE):
    # Load existing keys
    try:
        with open(PRIVATE_KEY_FILE, 'rb') as f:
            private_pem = f.read()
        with open(PUBLIC_KEY_FILE, 'rb') as f:
            public_pem = f.read().decode('utf-8')
        
        private_key = serialization.load_pem_private_key(private_pem, password=None)
        public_key = enc.deserialize_public_key(public_pem)
        print("Loaded existing server RSA keys")
    except Exception as e:
        print(f"Error loading existing RSA keys: {e}")
        raise
else:
    # Generate new keys
    try:
        private_key, public_key = enc.generate_rsa_keypair()
        
        # Serialize keys
        private_pem = enc.serialize_private_key(private_key)
        public_pem = enc.serialize_public_key(public_key)
        if isinstance(public_pem, bytes):
            public_pem = public_pem.decode('utf-8')
        
        # Save server keys
        enc.save_private_key(private_key, PRIVATE_KEY_FILE)
        enc.save_public_key(public_key, PUBLIC_KEY_FILE)
        
        print("Generated and saved new server RSA keys")
    except Exception as e:
        print(f"Error generating RSA key pair: {e}")
        raise

def generate_self_signed_cert(san_list):
    try:
        cert = crypto.X509()
        cert.get_subject().CN = HOST  # Set CN to host from config.conf
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(10*365*24*60*60)  # 10 years validity

        # Add SAN for IP or domain
        cert.add_extensions([
            crypto.X509Extension(b"subjectAltName", False, ",".join(san_list).encode())
        ])

        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(crypto.PKey().from_cryptography_key(public_key))
        cert.sign(crypto.PKey().from_cryptography_key(private_key), 'sha256')
        
        with open(CERT_FILE, 'wb') as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        with open(KEY_FILE, 'wb') as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, crypto.PKey().from_cryptography_key(private_key)))
        
        print(f"Generated new certificate with CN={HOST}, SAN={san_list}")
    except Exception as e:
        print(f"Error generating certificate: {e}")
        raise

# Generate self-signed certificate with SAN for the host if not present
# Only generate if cert/key files do not exist
if not (os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE)):
    print(f"Certificate or key missing. Generating new certificate for {HOST}")
    # Use san_list from chat_app.py or build it here from config
    config = configparser.ConfigParser()
    config.read('config.conf')
    local_ip = config['Network']['host']
    public_ip = config['Network'].get('public_ip', '').strip() if 'public_ip' in config['Network'] else ''
    san_list = [f"IP:{local_ip}"]
    if public_ip:
        san_list.append(f"IP:{public_ip}")
    generate_self_signed_cert(san_list)
else:
    print(f"Certificate and key already exist. Not regenerating.")

# Check if certificate exists and is valid for the host
def is_certificate_valid():
    if not os.path.exists(CERT_FILE) or not os.path.exists(KEY_FILE):
        return False
    try:
        with open(CERT_FILE, 'rb') as f:
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
        cert_cn = cert.get_subject().CN
        san_ext = cert.get_extension_count()
        san_match = False
        for i in range(san_ext):
            ext = cert.get_extension(i)
            if ext.get_short_name() == b'subjectAltName':
                san_data = str(ext).split(',')
                if HOST.replace('.', '').isdigit():
                    san_match = f"IP Address:{HOST}" in san_data or f"IP:{HOST}" in san_data
                else:
                    san_match = f"DNS:{HOST}" in san_data
                break
        print(f"Certificate check: CN={cert_cn}, SAN={san_data}, Valid={cert_cn == HOST and san_match}")
        return cert_cn == HOST and san_match
    except Exception as e:
        print(f"Error validating certificate: {e}")
        return False

def send_to_client(client_id, message):
    """Send encrypted message to a specific client"""
    if client_id in CLIENT_SOCKETS:
        try:
            client_socket, client_public_key = CLIENT_SOCKETS[client_id]
            encrypted_msg = enc.rsa_encrypt(client_public_key, json.dumps(message).encode('utf-8'))
            client_socket.send(encrypted_msg)
            return True
        except Exception as e:
            print(f"Error sending to client {client_id}: {e}")
            return False
    return False

def save_chat_history():
    """Save encrypted chat history to file"""
    try:
        with open('chat_history.json', 'w') as f:
            json.dump(CHAT_HISTORY, f, indent=2, default=str)
    except Exception as e:
        print(f"Error saving chat history: {e}")

def load_chat_history():
    """Load encrypted chat history from file"""
    try:
        with open('chat_history.json', 'r') as f:
            global CHAT_HISTORY
            CHAT_HISTORY = json.load(f)
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"Error loading chat history: {e}")

def save_room_history():
    """Save encrypted room history to file"""
    try:
        with open('room_history.json', 'w') as f:
            json.dump(ROOM_HISTORY, f, indent=2, default=str)
    except Exception as e:
        print(f"Error saving room history: {e}")

def load_room_history():
    """Load encrypted room history from file"""
    try:
        with open('room_history.json', 'r') as f:
            global ROOM_HISTORY
            ROOM_HISTORY = json.load(f)
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"Error loading room history: {e}")

def encrypt_message(message):
    """Encrypt a message for storage"""
    return enc.fernet_encrypt(CIPHER, json.dumps(message).encode('utf-8')).decode('utf-8')

def decrypt_message(encrypted_message):
    """Decrypt a message from storage"""
    try:
        decrypted = enc.fernet_decrypt(CIPHER, encrypted_message.encode('utf-8'))
        return json.loads(decrypted.decode('utf-8'))
    except Exception as e:
        print(f"Error decrypting message: {e}")
        return None

# find_user_server function removed - simplified federation uses broadcast approach

def parse_server_address(server_id):
    """Parse server address from various formats"""
    if ':' in server_id:
        # Format: host:port (e.g., 192.168.0.10:8443, myserver.com:8443)
        try:
            host, port_str = server_id.rsplit(':', 1)
            port = int(port_str)
            return host, port
        except ValueError:
            print(f"Invalid port in server_id: {server_id}")
            return None, None
    elif '_' in server_id:
        # Format: host_port (e.g., 192_168_0_10_8443)
        parts = server_id.split('_')
        if len(parts) >= 2:
            # Reconstruct host from parts (e.g., 192_168_0_10 -> 192.168.0.10)
            host = '.'.join(parts[:-1])  # All parts except last
            try:
                port = int(parts[-1])  # Last part is port
                return host, port
            except ValueError:
                port = 8443  # Default port
                return host, port
        else:
            return None, None
    else:
        # Assume it's just a hostname/IP with default port
        host = server_id
        port = 8443  # Default port
        return host, port

def ping_server(server_id, host=None, port=None):
    """Ping a server to check if it's online"""
    try:
        # If we don't have connection details, try to extract from server_id
        if not host or not port:
            host, port = parse_server_address(server_id)
            if host is None or port is None:
                return False
        
        # Create a simple socket connection (no TLS for ping)
        ping_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ping_socket.settimeout(3)  # 3 second timeout for ping
        result = ping_socket.connect_ex((host, port))
        ping_socket.close()
        
        return result == 0  # 0 means success
    except Exception as e:
        print(f"Ping failed for {server_id} ({host}:{port}): {e}")
        return False

def route_message(target_client, message):
    """Route message to target client (local or federated)"""
    # Check if target is local
    if target_client in CLIENT_SOCKETS:
        return send_to_client(target_client, message)
    
    # Route to federated servers
    for server_id in FEDERATED_SERVERS.keys():
        federated_message = {
            'type': 'federated_message',
            'target_client': target_client,
            'message': message,
            'from_server': LOCAL_CLIENT_ID
        }
        if send_to_federated_server(server_id, federated_message):
            return True
    
    return False

def handle_chat_request(from_client, to_client):
    """Handle chat request from one client to another"""
    # Check if target is local
    if to_client in CLIENT_SOCKETS:
        request_msg = {
            'status': 'chat_request',
            'from_client': from_client,
            'message': f'Client {from_client} wants to chat with you. Accept?'
        }
        
        if send_to_client(to_client, request_msg):
            PENDING_CONNECTIONS[from_client] = to_client
            print(f"Chat request sent from {from_client} to {to_client}")
            return True
    else:
        # Route to federated servers
        federated_message = {
            'type': 'chat_request',
            'from_client': from_client,
            'to_client': to_client,
            'from_server': LOCAL_CLIENT_ID
        }
        
        for server_id in FEDERATED_SERVERS.keys():
            if send_to_federated_server(server_id, federated_message):
                print(f"Chat request routed to federated server {server_id}")
                return True
    
    # If target not found
    send_to_client(from_client, {
        'status': 'error', 
        'message': f'Client {to_client} is not online'
    })
    return False

def handle_chat_response(from_client, to_client, accepted):
    """Handle chat response (accept/reject) from target client"""
    if accepted:
        # Create chat session
        session_id = f"{min(from_client, to_client)}_{max(from_client, to_client)}"
        CHAT_SESSIONS[session_id] = (from_client, to_client)
        
        # Notify both clients
        send_to_client(from_client, {
            'status': 'chat_accepted',
            'to_client': to_client,
            'session_id': session_id
        })
        
        # Route to target if not local
        if to_client not in CLIENT_SOCKETS:
            route_message(to_client, {
                'status': 'chat_accepted',
                'to_client': from_client,
                'session_id': session_id
            })
        else:
            send_to_client(to_client, {
                'status': 'chat_accepted',
                'to_client': from_client,
                'session_id': session_id
            })
        
        print(f"Chat session established between {from_client} and {to_client}")
    else:
        # Notify requesting client of rejection
        send_to_client(from_client, {
            'status': 'chat_rejected',
            'to_client': to_client
        })
        print(f"Chat request from {from_client} to {to_client} was rejected")
    
    # Clean up pending request
    if from_client in PENDING_CONNECTIONS:
        del PENDING_CONNECTIONS[from_client]

def handle_chat_message(from_client, to_client, message):
    """Handle chat message between two clients"""
    session_id = f"{min(from_client, to_client)}_{max(from_client, to_client)}"
    
    if session_id not in CHAT_SESSIONS:
        send_to_client(from_client, {
            'status': 'error',
            'message': 'No active chat session with this client'
        })
        return
    
    # Forward message to target client
    chat_msg = {
        'status': 'chat_message',
        'from_client': from_client,
        'message': message
    }
    
    if to_client in CLIENT_SOCKETS:
        # Local client
        if send_to_client(to_client, chat_msg):
            print(f"Chat message forwarded from {from_client} to {to_client}")
    else:
        # Federated client
        if route_message(to_client, chat_msg):
            print(f"Chat message routed from {from_client} to {to_client}")
        else:
            send_to_client(from_client, {
                'status': 'error',
                'message': f'Failed to send message to {to_client}'
            })

def handle_federated_message(msg_data, from_server):
    try:
        print(f"[FED-DEBUG] handle_federated_message called with: {msg_data} from {from_server}")
        msg_type = msg_data.get('type')
        print(f"[FED-DEBUG] Received federated message from {from_server}: {msg_type}")
        
        # Import INPROCESS_BACKENDS for use in this function
        from server import INPROCESS_BACKENDS
        
        if msg_type == 'federated_message':
            target_client = msg_data['target_client']
            message = msg_data['message']
            
            # Check if target is local
            if target_client in CLIENT_SOCKETS:
                send_to_client(target_client, message)
            else:
                # Route to other federated servers
                for server_id in FEDERATED_SERVERS.keys():
                    if server_id != from_server:
                        send_to_federated_server(server_id, msg_data)
        
        elif msg_type == 'chat_request':
            from_client = msg_data['from_client']
            to_client = msg_data['to_client']
            
            # Check if target is local
            if to_client in CLIENT_SOCKETS:
                handle_chat_request(from_client, to_client)
            else:
                # Route to other federated servers
                for server_id in FEDERATED_SERVERS.keys():
                    if server_id != from_server:
                        send_to_federated_server(server_id, msg_data)
        
        elif msg_type == 'direct_chat_request':
            # Direct chat request to a specific user
            from_server_id = msg_data['from_server']
            to_server_id = msg_data['to_server']
            from_client = msg_data['from_client']
            to_client = msg_data.get('to_client')
            message = msg_data.get('message', f'Chat request from {from_client}')
            
            # If this is the target server, notify the specific user
            if to_server_id == LOCAL_CLIENT_ID:
                if to_client and to_client in CLIENT_SOCKETS:
                    # Send to specific user
                    send_to_client(to_client, {
                        'type': 'direct_chat_request',
                        'from_client': from_client,
                        'from_server': from_server_id,
                        'message': message
                    })
                elif to_client and to_client in INPROCESS_BACKENDS:
                    # Send to in-process backend
                    INPROCESS_BACKENDS[to_client].receive_federated_message({
                        'type': 'direct_chat_request',
                        'from_client': from_client,
                        'from_server': from_server_id,
                        'message': message
                    })
                else:
                    # Send to all local clients if no specific target
                    for client_id in CLIENT_SOCKETS:
                        send_to_client(client_id, {
                            'type': 'direct_chat_request',
                            'from_client': from_client,
                            'from_server': from_server_id,
                            'message': message
                        })
            else:
                # Route to other federated servers
                for server_id in FEDERATED_SERVERS.keys():
                    if server_id != from_server:
                        send_to_federated_server(server_id, msg_data)
        
        elif msg_type == 'ping':
            # Handle ping message (keepalive)
            print(f"Received ping from federated server {from_server}")
        
        elif msg_type == 'server_connect':
            # Another server is connecting to us
            server_id = msg_data['server_id']
            server_public_key = enc.deserialize_public_key(msg_data['public_key'].encode('utf-8'))
            
            # Send acceptance
            response = {
                'status': 'accepted',
                'public_key': enc.serialize_public_key(server_public_key)
            }
            # Note: server_socket is not available in this context
            # This will be handled in the main server loop when servers connect
            print(f"Federated server {server_id} connection request received")

        elif msg_type == 'direct_chat_response':
            # Handle direct chat response (accept/reject)
            from_server_id = msg_data['from_server']
            to_server_id = msg_data['to_server']
            from_client = msg_data['from_client']
            to_client = msg_data.get('to_client')
            response = msg_data.get('response')
            
            # If this is the target server, notify the specific user
            if to_server_id == LOCAL_CLIENT_ID:
                if to_client and to_client in CLIENT_SOCKETS:
                    # Send to specific user
                    send_to_client(to_client, {
                        'type': 'direct_chat_response',
                        'from_client': from_client,
                        'response': response
                    })
                elif to_client and to_client in INPROCESS_BACKENDS:
                    # Send to in-process backend
                    INPROCESS_BACKENDS[to_client].receive_federated_message({
                        'type': 'direct_chat_response',
                        'from_client': from_client,
                        'response': response
                    })
                else:
                    # Send to all local clients if no specific target
                    for client_id in CLIENT_SOCKETS:
                        send_to_client(client_id, {
                            'type': 'direct_chat_response',
                            'from_client': from_client,
                            'response': response
                        })
            else:
                # Route to other federated servers
                for server_id in FEDERATED_SERVERS.keys():
                    if server_id != from_server:
                        send_to_federated_server(server_id, msg_data)
        
        elif msg_type == 'direct_chat_message':
            # Relay direct chat message to federated server or local client
            to_server = msg_data.get('to_server')
            chat_message = msg_data.get('message')
            from_client = msg_data.get('from_client', None)
            # If the target is this server, deliver to all local clients (or a specific one if from_client is set)
            if to_server == LOCAL_CLIENT_ID:
                for client_id in CLIENT_SOCKETS:
                    send_to_client(client_id, {
                        'status': 'direct_chat_message',
                        'from_client': from_client or from_server,
                        'message': chat_message
                    })
            else:
                # Route to other federated servers
                for server_id in FEDERATED_SERVERS.keys():
                    if server_id != from_server:
                        send_to_federated_server(server_id, msg_data)
        
        elif msg_type == 'chat_message':
            # Handle chat message between users
            from_client = msg_data['from_client']
            to_client = msg_data['to_client']
            message = msg_data['message']
            print(f"Received chat message from {from_client} to {to_client}: {message}")
            
            # Check if target is local
            if to_client in CLIENT_SOCKETS:
                # Deliver to local client
                print(f"Delivering chat message to local client {to_client}")
                send_to_client(to_client, {
                    'status': 'chat_message',
                    'from_client': from_client,
                    'message': message
                })
                # Also deliver to in-process backend if present
                from server import INPROCESS_BACKENDS
                if to_client in INPROCESS_BACKENDS:
                    print(f"Delivering chat message to in-process backend {to_client}")
                    INPROCESS_BACKENDS[to_client].receive_federated_message({
                        'type': 'chat_message',
                        'from_client': from_client,
                        'message': message
                    })
            else:
                print(f"Target client {to_client} not found locally, routing to other federated servers")
                # Route to other federated servers
                for server_id in FEDERATED_SERVERS.keys():
                    if server_id != from_server:
                        send_to_federated_server(server_id, msg_data)
        
        elif msg_type == 'get_users':
            print(f"[FED-DEBUG] receive_federated_message handling get_users from {msg_data.get('from_server')}")
            from_server = msg_data.get('from_server')
            from server import CLIENT_SOCKETS, INPROCESS_BACKENDS, CLIENT_KEYS, LOCAL_CLIENT_ID, HOST, PORT, send_to_federated_server
            local_users = get_all_online_users(CLIENT_SOCKETS, INPROCESS_BACKENDS, CLIENT_KEYS, LOCAL_CLIENT_ID, HOST, PORT)
            response = {
                'type': 'user_list_response',
                'from_server': LOCAL_CLIENT_ID,
                'to_server': from_server,
                'users': local_users,
                'server_address': f"{HOST}:{PORT}"
            }
            print(f"[FED-DEBUG] Sending user_list_response to {from_server}: {response}")
            send_to_federated_server(from_server, response)
        
        elif msg_type == 'user_list_response':
            print(f"[FED-DEBUG] Received user_list_response from {from_server}: {msg_data}")
            # Handle user list response from federated server
            users = msg_data.get('users', [])
            from_server = msg_data.get('from_server')
            server_address = msg_data.get('server_address', from_server)
            print(f"Backend received user_list_response from {from_server} (address: {server_address}): {users}")
            # Simplified federation: no user directory, just deliver to backends
            # Deliver to all in-process backends
            for backend in INPROCESS_BACKENDS.values():
                backend.receive_federated_message({
                    'type': 'user_list_response',
                    'users': users,
                    'from_server': from_server,
                    'server_address': server_address
                })
        elif msg_type == 'room_message':
            # Deliver to all in-process backends
            for backend in INPROCESS_BACKENDS.values():
                backend.receive_federated_message({
                    'type': 'room_message',
                    'room_name': msg_data.get('room_name'),
                    'from_client': msg_data.get('from_client'),
                    'message': msg_data.get('message')
                })
        elif msg_type == 'room_join_request':
            # Deliver to all in-process backends
            for backend in INPROCESS_BACKENDS.values():
                backend.receive_federated_message({
                    'type': 'room_invite',
                    'room_name': msg_data.get('room_name'),
                    'from_client': msg_data.get('from_client')
                })
        elif msg_type == 'room_join_response':
            # Deliver to all in-process backends
            for backend in INPROCESS_BACKENDS.values():
                backend.receive_federated_message({
                    'type': 'room_join_response',
                    'room_name': msg_data.get('room_name'),
                    'from_client': msg_data.get('from_client'),
                    'accepted': msg_data.get('accepted', False)
                })
        elif msg_type == 'room_invitation':
            # Deliver to all in-process backends
            for backend in INPROCESS_BACKENDS.values():
                backend.receive_federated_message({
                    'type': 'room_invitation',
                    'room_name': msg_data.get('room_name'),
                    'from_client': msg_data.get('from_client')
                })
        elif msg_type == 'online_check_response':
            # Handle online check response
            from_client = msg_data.get('from_client')
            to_client = msg_data.get('to_client')
            is_online = msg_data.get('online', False)
            print(f"Backend received online check response: {from_client} is {'online' if is_online else 'offline'}")
            # Deliver to all in-process backends
            for backend in INPROCESS_BACKENDS.values():
                backend.receive_federated_message({
                    'type': 'online_check_response',
                    'from_client': from_client,
                    'to_client': to_client,
                    'online': is_online
                })
        elif msg_type == 'federated_users':
            # Merge federated users into the client's user list
            federated_users = msg_data.get('users', [])
            print(f"Backend received federated users: {federated_users}")
            # Simplified federation: no user directory, just deliver to backends
            self.outbox.put({
                'type': 'federated_users',
                'users': federated_users,
                'from_server': msg_data.get('from_server')
            })
        else:
            # For any other message types, preserve the original structure
            print(f"Backend putting unknown message type to outbox: {msg_data}")
            # Deliver to all in-process backends
            for backend in INPROCESS_BACKENDS.values():
                backend.receive_federated_message(msg_data)
    except Exception as e:
        print(f"[FED-DEBUG] Error in handle_federated_message: {e}")
        import traceback
        traceback.print_exc()

def run_server(client_id):
    server_socket = None
    try:
        # Load persistent data
        load_chat_history()
        load_room_history()
        
        # Start periodic save thread
        def periodic_save():
            while True:
                try:
                    time.sleep(60)  # Save every minute
                    save_chat_history()
                    save_room_history()
                    print("Server: Saved persistent data")
                except Exception as e:
                    print(f"Error in server periodic save: {e}")
                    time.sleep(5)
        
        save_thread = threading.Thread(target=periodic_save, daemon=True)
        save_thread.start()
        
        # Initialize server socket with TLS
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket = context.wrap_socket(server_socket, server_side=True)
        server_socket.setblocking(True)  # Ensure blocking mode
        server_socket.bind((HOST, PORT))
        server_socket.listen(5)
        print(f"Federated server listening on {HOST}:{PORT} (Client ID: {client_id})")

        def handle_connection(client_socket, address):
            """Handle both client and server connections"""
            try:
                print(f"New connection attempt from {address}")
                # Receive initial data
                client_socket.settimeout(10)  # 10-second timeout for initial data
                data = client_socket.recv(4096).decode('utf-8')
                print(f"Received data from {address}: '{data}' (length: {len(data)})")
                if not data:
                    print(f"No data received from {address}")
                    return
                
                connection_info = json.loads(data)
                print(f"Parsed connection info: {connection_info}")
                
                # Check if this is a server connection
                if 'type' in connection_info and connection_info['type'] == 'server_connect':
                    print(f"Handling server connection from {address}")
                    handle_server_connection(client_socket, connection_info, address)
                else:
                    print(f"Handling client connection from {address}")
                    # This is a client connection
                    handle_client_connection(client_socket, connection_info, address)
                    
            except json.JSONDecodeError as e:
                print(f"JSON decode error from {address}: {e}")
                client_socket.close()
            except Exception as e:
                print(f"Error handling connection from {address}: {e}")
                client_socket.close()

        while True:
            try:
                client_socket, address = server_socket.accept()
                client_socket.setblocking(True)  # Ensure blocking mode
                threading.Thread(target=handle_connection, args=(client_socket, address), daemon=True).start()
            except ssl.SSLError as e:
                print(f"SSL handshake error: {e}")
            except Exception as e:
                print(f"Error accepting connection: {e}")
                continue
    except Exception as e:
        print(f"Server error: {e}")
        raise
    finally:
        if server_socket:
            server_socket.close()
            print("Server socket closed")

class ServerBackend:
    def __init__(self, client_id):
        self.client_id = client_id
        global LOCAL_CLIENT_ID
        LOCAL_CLIENT_ID = client_id
        self.inbox = queue.Queue()  # Messages from client
        self.outbox = queue.Queue() # Messages to client
        self.active_chats = {}      # Chat sessions
        # Start federated message listener
        self._stop_event = threading.Event()
        self.federated_listener_thread = threading.Thread(target=self._federated_listener, daemon=True)
        self.federated_listener_thread.start()
        # Register this backend for federated delivery
        INPROCESS_BACKENDS[client_id] = self

    def _federated_listener(self):
        # Poll for new federated messages and deliver to client outbox
        from server import FEDERATED_SERVERS, handle_federated_server
        while not self._stop_event.is_set():
            # For each federated server, check for new messages
            # (In this design, handle_federated_server already routes to send_to_client, which is not in-process)
            # Instead, we need to poll a shared queue or similar. For now, sleep.
            time.sleep(0.2)
            # If you want to implement a shared queue for federated->local, do it here.
            # For now, federated messages will be delivered via send_to_client below.

    def send_message_from_client(self, message):
        # Called by the client GUI to send a message to the backend
        self.outbox.put({
            'type': 'chat_message',
            'from': self.client_id,
            'message': message
        })

    def get_message_for_client(self, timeout=0.1):
        try:
            return self.outbox.get(timeout=timeout)
        except queue.Empty:
            return None

    def handle_client_command(self, command, args):
        print(f"[FED-DEBUG] handle_client_command called with: {command} {args}")
        global CLIENT_SOCKETS, INPROCESS_BACKENDS, LOCAL_CLIENT_ID, CLIENT_KEYS, HOST, PORT
        command = command.strip().lower()
        print(f"[DEBUG] Checking command: {command}")
        from server import FEDERATED_SERVERS, send_to_federated_server, LOCAL_CLIENT_ID
        if command == 'approve_federated_connection':
            server_id = args.strip()
            from server import approve_federated_connection
            if approve_federated_connection(server_id):
                self.outbox.put({'type': 'info', 'message': f'Federated connection approved for {server_id}'})
            else:
                self.outbox.put({'type': 'error', 'message': f'No pending connection for {server_id}'})
        elif command == 'reject_federated_connection':
            server_id = args.strip()
            from server import reject_federated_connection
            if reject_federated_connection(server_id):
                self.outbox.put({'type': 'info', 'message': f'Federated connection rejected for {server_id}'})
            else:
                self.outbox.put({'type': 'error', 'message': f'No pending connection for {server_id}'})
        elif command == 'connect_server':
            try:
                parts = args.split()
                if len(parts) >= 3:
                    server_host, server_port, server_id = parts[0], int(parts[1]), parts[2]
                    from server import connect_to_federated_server
                    success = connect_to_federated_server(server_host, server_port, server_id)
                    if success:
                        self.outbox.put({'type': 'server_connected','server_id': server_id})
                    else:
                        self.outbox.put({'type': 'error','message': f'Failed to connect to server {server_id}'})
                else:
                    self.outbox.put({'type': 'error','message': 'Invalid connect_server arguments'})
            except Exception as e:
                self.outbox.put({'type': 'error','message': f'Exception: {e}'})
        elif command == 'chat_message':
            # Args: target_user message
            parts = args.split(' ', 1)
            if len(parts) == 2:
                target_user, message = parts
                if target_user == self.client_id:
                    self.outbox.put({'type': 'error', 'message': 'Cannot send message to yourself'})
                    return
                
                # Check if target is local
                from server import CLIENT_SOCKETS
                if target_user in CLIENT_SOCKETS:
                    # Local user - use existing chat system
                    from server import handle_chat_message
                    handle_chat_message(self.client_id, target_user, message)
                else:
                    # Simplified federation: send to all connected federated servers
                    # In this approach, we broadcast to all federated servers
                    from server import FEDERATED_SERVERS, send_to_federated_server
                    print(f"Routing chat message to {target_user} via all federated servers")
                    print(f"FEDERATED_SERVERS: {list(FEDERATED_SERVERS.keys())}")
                    
                    if FEDERATED_SERVERS:
                        federated_message = {
                            'type': 'chat_message',
                            'from_client': self.client_id,
                            'to_client': target_user,
                            'message': message
                        }
                        print(f"Sending federated message: {federated_message}")
                        
                        # Send to all federated servers
                        sent_count = 0
                        for server_id in FEDERATED_SERVERS.keys():
                            if send_to_federated_server(server_id, federated_message):
                                sent_count += 1
                                print(f"Successfully sent chat message to {target_user} via {server_id}")
                        
                        if sent_count > 0:
                            print(f"Sent message to {sent_count} federated servers")
                        else:
                            print(f"Failed to send chat message to any federated server")
                            self.outbox.put({'type': 'error', 'message': f'Failed to send message to {target_user}'})
                    else:
                        print(f"No federated servers connected")
                        self.outbox.put({'type': 'error', 'message': f'No federated servers available to reach {target_user}'})
            else:
                self.outbox.put({'type': 'error', 'message': 'Invalid chat_message format'})
        elif command == 'list_clients':
            self.outbox.put({'type': 'info', 'message': 'Federation now uses only server addresses. No user list.'})
        elif command == 'get_federated_users':
            self.outbox.put({'type': 'info', 'message': 'Federation now uses only server addresses. No user list.'})
        elif command == 'direct_chat_request':
            # Args: user_id display_name
            parts = args.split(' ', 1)
            if len(parts) == 2:
                target_user, display_name = parts
                # Simplified federation: send to all connected federated servers
                from server import FEDERATED_SERVERS, send_to_federated_server
                
                if FEDERATED_SERVERS:
                    federated_message = {
                        'type': 'direct_chat_request',
                        'from_server': LOCAL_CLIENT_ID,
                        'to_server': 'broadcast',  # Broadcast to all servers
                        'from_client': self.client_id,
                        'to_client': target_user,
                        'message': f'User {self.client_id} wants to chat with you.'
                    }
                    
                    # Send to all federated servers
                    sent_count = 0
                    for server_id in FEDERATED_SERVERS.keys():
                        if send_to_federated_server(server_id, federated_message):
                            sent_count += 1
                    
                    if sent_count > 0:
                        self.outbox.put({'type': 'info', 'message': f'Sent chat request to {target_user} via {sent_count} servers'})
                    else:
                        self.outbox.put({'type': 'error', 'message': f'Failed to send chat request to {target_user}'})
                else:
                    self.outbox.put({'type': 'error', 'message': f'No federated servers available to reach {target_user}'})
            else:
                self.outbox.put({'type': 'error', 'message': 'Invalid direct_chat_request format'})
        elif command == 'direct_chat_message':
            # Args: server_id message
            parts = args.split(' ', 1)
            if len(parts) == 2:
                target_server, chat_message = parts
                if target_server in FEDERATED_SERVERS:
                    federated_message = {
                        'type': 'direct_chat_message',
                        'from_server': LOCAL_CLIENT_ID,
                        'to_server': target_server,
                        'message': chat_message,
                        'from_client': self.client_id
                    }
                    send_to_federated_server(target_server, federated_message)
                else:
                    self.outbox.put({'type': 'error', 'message': f'Server {target_server} not found'})
            else:
                self.outbox.put({'type': 'error', 'message': 'Invalid direct_chat_message format'})
        elif command == 'direct_chat_response':
            # Args: from_user accept/reject
            parts = args.split(' ', 1)
            if len(parts) == 2:
                from_user, response = parts
                # Simplified federation: send to all connected federated servers
                from server import FEDERATED_SERVERS, send_to_federated_server
                
                if FEDERATED_SERVERS:
                    federated_message = {
                        'type': 'direct_chat_response',
                        'from_server': LOCAL_CLIENT_ID,
                        'to_server': 'broadcast',  # Broadcast to all servers
                        'from_client': self.client_id,
                        'to_client': from_user,
                        'response': response
                    }
                    
                    # Send to all federated servers
                    sent_count = 0
                    for server_id in FEDERATED_SERVERS.keys():
                        if send_to_federated_server(server_id, federated_message):
                            sent_count += 1
                    
                    if sent_count == 0:
                        self.outbox.put({'type': 'error', 'message': f'Failed to send response to {from_user}'})
                else:
                    self.outbox.put({'type': 'error', 'message': f'No federated servers available to reach {from_user}'})
            else:
                self.outbox.put({'type': 'error', 'message': 'Invalid direct_chat_response format'})
        elif command == 'chat_response':
            # Args: from_server accept/reject
            parts = args.split(' ', 1)
            if len(parts) == 2:
                from_server, response = parts
                # Send response to federated server
                if from_server in FEDERATED_SERVERS:
                    federated_message = {
                        'type': 'direct_chat_response',
                        'from_server': LOCAL_CLIENT_ID,
                        'to_server': from_server,
                        'response': response
                    }
                    send_to_federated_server(from_server, federated_message)
                else:
                    self.outbox.put({'type': 'error', 'message': f'Server {from_server} not found'})
            else:
                self.outbox.put({'type': 'error', 'message': 'Invalid chat_response format'})
        elif command == 'connection_request':
            # Args: server_address (can be host:port, host_port, or just host)
            try:
                server_address = args.strip()
                if not server_address:
                    self.outbox.put({'type': 'error','message': 'No server address provided'})
                    return
                
                # Parse the server address
                from server import parse_server_address, HOST, PORT
                server_host, server_port = parse_server_address(server_address)
                if server_host is None or server_port is None:
                    self.outbox.put({'type': 'error','message': f'Invalid server address format: {server_address}'})
                    return
                
                # Don't connect to ourselves
                if server_host == HOST and server_port == PORT:
                    self.outbox.put({'type': 'error','message': f'Cannot connect to yourself ({server_address})'})
                    return
                
                # Generate server_id from the address
                server_id = server_address.replace(':', '_').replace('.', '_')
                
                # Don't connect to ourselves
                if server_id == LOCAL_CLIENT_ID:
                    self.outbox.put({'type': 'error','message': f'Cannot connect to yourself'})
                    return
                
                # Run connection in a separate thread to avoid blocking
                def connect_async():
                    try:
                        from server import connect_to_federated_server
                        success = connect_to_federated_server(server_host, server_port, server_id)
                        if success:
                            self.outbox.put({'type': 'server_connected','server_id': server_id})
                        else:
                            self.outbox.put({'type': 'error','message': f'Failed to connect to server {server_address}'})
                    except Exception as e:
                        self.outbox.put({'type': 'error','message': f'Connection exception: {e}'})
                
                threading.Thread(target=connect_async, daemon=True).start()
            except Exception as e:
                self.outbox.put({'type': 'error','message': f'Exception: {e}'})
        elif command == 'room_message':
            # Args: room_name message
            parts = args.split(' ', 1)
            if len(parts) == 2:
                room_name, message = parts
                # Send room message to all room members
                from server import INPROCESS_BACKENDS
                for backend in INPROCESS_BACKENDS.values():
                    backend.receive_federated_message({
                        'type': 'room_message',
                        'room_name': room_name,
                        'from_client': self.client_id,
                        'message': message
                    })
            else:
                self.outbox.put({'type': 'error', 'message': 'Invalid room_message format'})
        elif command == 'room_join_request':
            # Args: target_user room_name
            parts = args.split(' ', 1)
            if len(parts) == 2:
                target_user, room_name = parts
                # Simplified federation: send to all connected federated servers
                from server import FEDERATED_SERVERS, send_to_federated_server
                
                if FEDERATED_SERVERS:
                    federated_message = {
                        'type': 'room_join_request',
                        'from_client': self.client_id,
                        'to_client': target_user,
                        'room_name': room_name
                    }
                    
                    # Send to all federated servers
                    sent_count = 0
                    for server_id in FEDERATED_SERVERS.keys():
                        if send_to_federated_server(server_id, federated_message):
                            sent_count += 1
                    
                    if sent_count == 0:
                        self.outbox.put({'type': 'error', 'message': f'Failed to send room join request to {target_user}'})
                else:
                    self.outbox.put({'type': 'error', 'message': f'No federated servers available to reach {target_user}'})
            else:
                self.outbox.put({'type': 'error', 'message': 'Invalid room_join_request format'})
        elif command == 'room_join_accept':
            # Args: from_user room_name
            parts = args.split(' ', 1)
            if len(parts) == 2:
                from_user, room_name = parts
                # Simplified federation: send to all connected federated servers
                from server import FEDERATED_SERVERS, send_to_federated_server
                
                if FEDERATED_SERVERS:
                    federated_message = {
                        'type': 'room_join_response',
                        'from_client': self.client_id,
                        'to_client': from_user,
                        'room_name': room_name,
                        'accepted': True
                    }
                    
                    # Send to all federated servers
                    sent_count = 0
                    for server_id in FEDERATED_SERVERS.keys():
                        if send_to_federated_server(server_id, federated_message):
                            sent_count += 1
                    
                    if sent_count == 0:
                        self.outbox.put({'type': 'error', 'message': f'Failed to send room join acceptance to {from_user}'})
                else:
                    self.outbox.put({'type': 'error', 'message': f'No federated servers available to reach {from_user}'})
            else:
                self.outbox.put({'type': 'error', 'message': 'Invalid room_join_accept format'})
        elif command == 'room_join_reject':
            # Args: from_user room_name
            parts = args.split(' ', 1)
            if len(parts) == 2:
                from_user, room_name = parts
                # Simplified federation: send to all connected federated servers
                from server import FEDERATED_SERVERS, send_to_federated_server
                
                if FEDERATED_SERVERS:
                    federated_message = {
                        'type': 'room_join_response',
                        'from_client': self.client_id,
                        'to_client': from_user,
                        'room_name': room_name,
                        'accepted': False
                    }
                    
                    # Send to all federated servers
                    sent_count = 0
                    for server_id in FEDERATED_SERVERS.keys():
                        if send_to_federated_server(server_id, federated_message):
                            sent_count += 1
                    
                    if sent_count == 0:
                        self.outbox.put({'type': 'error', 'message': f'Failed to send room join rejection to {from_user}'})
                else:
                    self.outbox.put({'type': 'error', 'message': f'No federated servers available to reach {from_user}'})
            else:
                self.outbox.put({'type': 'error', 'message': 'Invalid room_join_reject format'})
        elif command == 'room_list_request':
            # Args: target_user
            target_user = args.strip()
            # Simplified federation: send to all connected federated servers
            from server import FEDERATED_SERVERS, send_to_federated_server
            
            if FEDERATED_SERVERS:
                federated_message = {
                    'type': 'room_list_request',
                    'from_client': self.client_id,
                    'to_client': target_user
                }
                
                # Send to all federated servers
                sent_count = 0
                for server_id in FEDERATED_SERVERS.keys():
                    if send_to_federated_server(server_id, federated_message):
                        sent_count += 1
                
                if sent_count == 0:
                    self.outbox.put({'type': 'error', 'message': f'Failed to send room list request to {target_user}'})
            else:
                self.outbox.put({'type': 'error', 'message': f'No federated servers available to reach {target_user}'})
        elif command == 'get_my_rooms':
            # Return the current user's rooms for federated requests
            # This will be called by the federated message handler
            # The actual room data is in the client GUI, so we'll return empty for now
            # In a full implementation, the client would send room data to the backend
            self.outbox.put({
                'type': 'my_rooms',
                'rooms': []
            })
        elif command == 'room_list_response':
            # Handle room list response from client for federated requests
            # Args: from_user room_data_json
            parts = args.split(' ', 1)
            if len(parts) == 2:
                from_user, room_data_json = parts
                try:
                    rooms = json.loads(room_data_json)
                    # Send room list response to federated server
                    from server import FEDERATED_SERVERS
                    for server_id in FEDERATED_SERVERS.keys():
                        federated_message = {
                            'type': 'room_list_response',
                            'from_client': from_user,
                            'rooms': rooms
                        }
                        send_to_federated_server(server_id, federated_message)
                except json.JSONDecodeError:
                    self.outbox.put({'type': 'error', 'message': 'Invalid room data format'})
            else:
                self.outbox.put({'type': 'error', 'message': 'Invalid room_list_response format'})
        elif command == 'room_invitation':
            # Args: target_user room_name
            parts = args.split(' ', 1)
            if len(parts) == 2:
                target_user, room_name = parts
                print(f"Processing room invitation from {self.client_id} to {target_user} for room {room_name}")
                # Simplified federation: send to all connected federated servers
                from server import FEDERATED_SERVERS, send_to_federated_server
                
                if FEDERATED_SERVERS:
                    federated_message = {
                        'type': 'room_invitation',
                        'from_client': self.client_id,
                        'to_client': target_user,
                        'room_name': room_name
                    }
                    print(f"Sending federated room invitation: {federated_message}")
                    
                    # Send to all federated servers
                    sent_count = 0
                    for server_id in FEDERATED_SERVERS.keys():
                        if send_to_federated_server(server_id, federated_message):
                            sent_count += 1
                    
                    if sent_count > 0:
                        print(f"Sent room invitation to {sent_count} federated servers")
                    else:
                        print(f"Failed to send room invitation to any federated server")
                        self.outbox.put({'type': 'error', 'message': f'Failed to send room invitation to {target_user}'})
                else:
                    print(f"No federated servers connected")
                    self.outbox.put({'type': 'error', 'message': f'No federated servers available to reach {target_user}'})
            else:
                print(f"Invalid room_invitation format. Args: '{args}'")
                self.outbox.put({'type': 'error', 'message': 'Invalid room_invitation format'})
        elif command == 'ping_server':
            # Args: server_id
            server_id = args.strip()
            from server import ping_server
            is_online = ping_server(server_id)
            self.outbox.put({
                'type': 'ping_response',
                'server_id': server_id,
                'online': is_online
            })
        elif command == 'online_check':
            # Args: target_user
            target_user = args.strip()
            # Simplified federation: send to all connected federated servers
            from server import FEDERATED_SERVERS, send_to_federated_server
            
            if FEDERATED_SERVERS:
                federated_message = {
                    'type': 'online_check',
                    'from_client': self.client_id,
                    'to_client': target_user
                }
                
                # Send to all federated servers
                sent_count = 0
                for server_id in FEDERATED_SERVERS.keys():
                    if send_to_federated_server(server_id, federated_message):
                        sent_count += 1
                
                if sent_count > 0:
                    print(f"Sent online check for {target_user} to {sent_count} federated servers")
                else:
                    print(f"Failed to send online check for {target_user}")
            else:
                print(f"No federated servers available for online check of {target_user}")
        elif command == 'fetch_federated_users':
            print(f"[FED-DEBUG] fetch_federated_users called for server_id: {args.strip()}")
            server_id = args.strip()
            if server_id in FEDERATED_SERVERS:
                federated_message = {
                    'type': 'get_users',
                    'from_server': LOCAL_CLIENT_ID
                }
                send_to_federated_server(server_id, federated_message)
                self.outbox.put({'type': 'info', 'message': f'Requested user list from {server_id}'})
            else:
                self.outbox.put({'type': 'error', 'message': f'Server {server_id} not connected'})
        elif command == 'get_user_directory':
            # User directory removed in simplified federation
            self.outbox.put({'type': 'info', 'message': 'User directory removed. Federation now uses only server addresses.'})
        else:
            print(f"[DEBUG] Unknown command in ServerBackend.handle_client_command: {command}")
            self.outbox.put({'type': 'error', 'message': f'Unknown or unimplemented command: {command}'})

    # Add a method to receive federated messages and push to outbox
    def receive_federated_message(self, msg):
        msg_type = msg.get('type', msg.get('status', 'unknown'))
        print(f"[FED-DEBUG] receive_federated_message called with: {msg_type} - {msg}")
        
        if msg_type == 'server_connected':
            self.outbox.put({
                'type': 'server_connected',
                'server_id': msg.get('server_id'),
                'host': msg.get('host'),
                'port': msg.get('port')
            })
        elif msg_type == 'direct_chat_request':
            self.outbox.put({
                'type': 'direct_chat_request',
                'from_server': msg.get('from_server'),
                'from_client': msg.get('from_client'),
                'message': msg.get('message', f'Chat request from {msg.get("from_client", "unknown")}')
            })
        elif msg_type == 'direct_chat_response':
            self.outbox.put({
                'type': 'direct_chat_response',
                'from_client': msg.get('from_client'),
                'response': msg.get('response', 'reject')
            })
        elif msg_type == 'direct_chat_message':
            self.outbox.put({
                'type': 'direct_chat_message',
                'from_client': msg.get('from_client', msg.get('from_server', 'Unknown')),
                'message': msg.get('message', '')
            })
        elif msg_type == 'chat_message':
            print(f"Backend putting chat message to outbox: {msg}")
            self.outbox.put({
                'type': 'chat_message',
                'from_client': msg.get('from_client'),
                'message': msg.get('message')
            })
        elif msg_type == 'error':
            self.outbox.put({
                'type': 'error',
                'message': msg.get('message', 'Unknown error')
            })
        elif msg_type == 'info':
            self.outbox.put({
                'type': 'info',
                'message': msg.get('message', 'Unknown info')
            })
        elif msg_type == 'federated_users':
            # Merge federated users into the client's user list
            federated_users = msg.get('users', [])
            print(f"Backend received federated users: {federated_users}")
            # Simplified federation: no user directory, just deliver to backends
            for backend in INPROCESS_BACKENDS.values():
                backend.receive_federated_message({
                    'type': 'federated_users',
                    'users': federated_users,
                    'from_server': msg.get('from_server')
                })
        elif msg_type == 'user_list_response':
            print(f"[FED-DEBUG] receive_federated_message user_list_response users: {msg.get('users', [])}")
            # Handle user list response from federated server
            federated_users = msg.get('users', [])
            from_server = msg.get('from_server')
            server_address = msg.get('server_address', from_server)
            print(f"Backend received user_list_response from {from_server} (address: {server_address}): {federated_users}")
            # Simplified federation: no user directory, just deliver to backends
            for backend in INPROCESS_BACKENDS.values():
                backend.receive_federated_message({
                    'type': 'user_list_response',
                    'users': federated_users,
                    'from_server': from_server,
                    'server_address': server_address
                })
        elif msg_type == 'room_message':
            # Deliver to all in-process backends
            for backend in INPROCESS_BACKENDS.values():
                backend.receive_federated_message({
                    'type': 'room_message',
                    'room_name': msg_data.get('room_name'),
                    'from_client': msg_data.get('from_client'),
                    'message': msg_data.get('message')
                })
        elif msg_type == 'room_join_request':
            # Deliver to all in-process backends
            for backend in INPROCESS_BACKENDS.values():
                backend.receive_federated_message({
                    'type': 'room_invite',
                    'room_name': msg_data.get('room_name'),
                    'from_client': msg_data.get('from_client')
                })
        elif msg_type == 'room_join_response':
            # Deliver to all in-process backends
            for backend in INPROCESS_BACKENDS.values():
                backend.receive_federated_message({
                    'type': 'room_join_response',
                    'room_name': msg_data.get('room_name'),
                    'from_client': msg_data.get('from_client'),
                    'accepted': msg_data.get('accepted', False)
                })
        elif msg_type == 'room_invitation':
            # Deliver to all in-process backends
            for backend in INPROCESS_BACKENDS.values():
                backend.receive_federated_message({
                    'type': 'room_invitation',
                    'room_name': msg_data.get('room_name'),
                    'from_client': msg_data.get('from_client')
                })
        elif msg_type == 'online_check_response':
            # Handle online check response
            from_client = msg_data.get('from_client')
            to_client = msg_data.get('to_client')
            is_online = msg_data.get('online', False)
            print(f"Backend received online check response: {from_client} is {'online' if is_online else 'offline'}")
            # Deliver to all in-process backends
            for backend in INPROCESS_BACKENDS.values():
                backend.receive_federated_message({
                    'type': 'online_check_response',
                    'from_client': from_client,
                    'to_client': to_client,
                    'online': is_online
                })
        elif msg_type == 'get_users':
            print(f"[FED-DEBUG] receive_federated_message handling get_users from {msg_data.get('from_server')}")
            from_server = msg_data.get('from_server')
            from server import CLIENT_SOCKETS, INPROCESS_BACKENDS, CLIENT_KEYS, LOCAL_CLIENT_ID, HOST, PORT, send_to_federated_server
            local_users = get_all_online_users(CLIENT_SOCKETS, INPROCESS_BACKENDS, CLIENT_KEYS, LOCAL_CLIENT_ID, HOST, PORT)
            response = {
                'type': 'user_list_response',
                'from_server': LOCAL_CLIENT_ID,
                'to_server': from_server,
                'users': local_users,
                'server_address': f"{HOST}:{PORT}"
            }
            print(f"[FED-DEBUG] Sending user_list_response to {from_server}: {response}")
            send_to_federated_server(from_server, response)
        else:
            # For any other message types, preserve the original structure
            print(f"Backend putting unknown message type to outbox: {msg}")
            # Deliver to all in-process backends
            for backend in INPROCESS_BACKENDS.values():
                backend.receive_federated_message(msg)

def handle_client_connection(client_socket, client_info, address):
    global CLIENT_SOCKETS, INPROCESS_BACKENDS, LOCAL_CLIENT_ID, CLIENT_KEYS, HOST, PORT
    """Handle connection from a client"""
    client_id = None
    client_public_key = None
    try:
        client_id = client_info['id']
        client_public_key_pem = client_info['public_key'].encode('utf-8')
        client_public_key = enc.deserialize_public_key(client_public_key_pem)
        print(f"Client connected: ID={client_id}, Address={address}")
        # Store client information
        CLIENT_SOCKETS[client_id] = (client_socket, client_public_key)
        CLIENT_KEYS[client_id] = client_public_key_pem
        # Store user credentials
        server_address = f"{HOST}:{PORT}"
        # Get all online users (local and federated)
        all_users = get_all_online_users(CLIENT_SOCKETS, INPROCESS_BACKENDS, CLIENT_KEYS, LOCAL_CLIENT_ID, HOST, PORT)
        # Send acceptance
        client_socket.send(enc.rsa_encrypt(client_public_key, json.dumps({
            'status': 'accepted', 
            'public_key': enc.serialize_public_key(enc.generate_rsa_keypair()[1]),
            'online_clients': list(CLIENT_SOCKETS.keys()),
            'all_users': all_users
        }).encode('utf-8')))
        print(f"Client {client_id} registered and connected")
        # Notify other clients about new connection
        for other_id in CLIENT_SOCKETS.keys():
            if other_id != client_id:
                send_to_client(other_id, {
                    'status': 'client_connected',
                    'client_id': client_id
                })
        while True:
            client_socket.settimeout(None)  # No timeout for messages
            try:
                encrypted_msg = client_socket.recv(4096)
                if not encrypted_msg:
                    print(f"Client {client_id} disconnected")
                    break
                try:
                    decrypted_msg = enc.rsa_decrypt(enc.generate_rsa_keypair()[0], encrypted_msg)
                    msg_data = json.loads(decrypted_msg.decode('utf-8'))
                    command = msg_data['command'].lower()
                    args = msg_data.get('args', '')
                    # ... rest of the handler unchanged ...
                except Exception as e:
                    print(f"Error handling client message from {client_id}: {e}")
                    traceback.print_exc()
                    break
            except Exception as e:
                print(f"Error receiving message from client {client_id}: {e}")
                traceback.print_exc()
                break
    except Exception as e:
        print(f"Error handling client connection from {address}: {e}")
        traceback.print_exc()
        client_socket.close()