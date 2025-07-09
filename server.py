import threading
import queue
import os
import json
import encryption_utils as enc
from federation import Federation
import media_utils
import secrets

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
        self.pending_file_offers = {}
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
        # --- File/media support ---
        elif msg.get('type') == 'file_key':
            # Store encrypted key/nonce for this file_id
            file_id = msg.get('file_id')
            data = msg.get('data')
            if not os.path.exists('media'):
                os.makedirs('media')
            key_path = os.path.join('media', f'{file_id}.key')
            with open(key_path, 'wb') as f:
                f.write(bytes.fromhex(data))
        elif msg.get('type') == 'file_metadata':
            contact = msg.get('from_client', peer_id)
            if not os.path.exists('media'):
                os.makedirs('media')
            file_id = msg.get('file_id')
            meta = msg.get('metadata', {})
            meta_path = os.path.join('media', f'{file_id}.meta.json')
            with open(meta_path, 'w') as f:
                json.dump(meta, f)
            # Track received chunks
            index_path = os.path.join('media', f'{file_id}.index.json')
            with open(index_path, 'w') as f:
                json.dump({'received': [], 'expected_size': meta.get('size', 0)}, f)
            self.outbox.put({
                'type': 'file_metadata',
                'from_client': contact,
                'from_server': peer_id,
                'file_id': file_id,
                'metadata': meta
            })
        elif msg.get('type') == 'file_chunk':
            file_id = msg.get('file_id')
            chunk_data = msg.get('data')
            chunk_idx = msg.get('chunk_idx', 0)
            if not os.path.exists('media'):
                os.makedirs('media')
            chunk_path = os.path.join('media', f'{file_id}.chunk{chunk_idx}')
            with open(chunk_path, 'wb') as f:
                f.write(bytes.fromhex(chunk_data))
            # Update index
            index_path = os.path.join('media', f'{file_id}.index.json')
            if os.path.exists(index_path):
                with open(index_path, 'r') as f:
                    index = json.load(f)
            else:
                index = {'received': [], 'expected_size': 0}
            index['received'].append(chunk_idx)
            with open(index_path, 'w') as f:
                json.dump(index, f)
            
            # Send progress update to client
            meta_path = os.path.join('media', f'{file_id}.meta.json')
            if os.path.exists(meta_path):
                with open(meta_path, 'r') as f:
                    meta = json.load(f)
                expected_size = meta.get('size', 0)
                if expected_size > 0:
                    # Calculate total received size to estimate total chunks
                    chunk_size = 99 * 1024 * 1024  # 99MB chunks
                    estimated_total_chunks = (expected_size + chunk_size - 1) // chunk_size
                    # Send progress update to client
                    self.outbox.put({
                        'type': 'file_chunk',
                        'file_id': file_id,
                        'chunk_num': len(index['received']),
                        'total_chunks': estimated_total_chunks
                    })
            
            # Check if all chunks received (by size)
            key_path = os.path.join('media', f'{file_id}.key')
            if os.path.exists(meta_path) and os.path.exists(key_path):
                with open(meta_path, 'r') as f:
                    meta = json.load(f)
                expected_size = meta.get('size', 0)
                # Calculate total received size
                total_size = 0
                chunk_files = []
                for idx in sorted(set(index['received'])):
                    cpath = os.path.join('media', f'{file_id}.chunk{idx}')
                    if os.path.exists(cpath):
                        total_size += os.path.getsize(cpath)
                        chunk_files.append(cpath)
                if total_size >= expected_size and expected_size > 0:
                    # Reassemble
                    enc_path = os.path.join('media', f'{file_id}.enc')
                    with open(enc_path, 'wb') as outf:
                        for cpath in chunk_files:
                            with open(cpath, 'rb') as cf:
                                outf.write(cf.read())
                    # Decrypt key/nonce
                    import encryption_utils as enc
                    with open(key_path, 'rb') as f:
                        encrypted_key_nonce = f.read()
                    try:
                        key_nonce = enc.rsa_decrypt(self.private_key, encrypted_key_nonce)
                        print(f"[DEBUG] key_nonce len: {len(key_nonce)}, hex: {key_nonce.hex()[:32]}...")
                        key = key_nonce[:32]
                        nonce = key_nonce[32:]
                        print(f"[DEBUG] key len: {len(key)}, hex: {key.hex()[:32]}...")
                        print(f"[DEBUG] nonce len: {len(nonce)}, hex: {nonce.hex()[:32]}...")
                        orig_filename = meta.get('orig_filename', file_id)
                        dec_path = os.path.join('media', f'{file_id}.decrypted_{orig_filename}')
                        # Print first 16 bytes of .enc file
                        with open(enc_path, 'rb') as fenc:
                            enc_head = fenc.read(16)
                            print(f"[DEBUG] .enc file first 16 bytes: {enc_head.hex()}")
                        media_utils.decrypt_file(enc_path, dec_path, key)
                        # Clean up temporary files, keep only the decrypted file
                        for fname in os.listdir('media'):
                            if fname.startswith(file_id) and not fname.endswith(f'decrypted_{orig_filename}'):
                                try:
                                    os.remove(os.path.join('media', fname))
                                except Exception as cleanup_err:
                                    print(f"[SERVER] Cleanup failed for {fname}: {cleanup_err}")
                        self.outbox.put({
                            'type': 'file_complete',
                            'file_id': file_id,
                            'decrypted_path': dec_path,
                            'orig_filename': orig_filename,
                            'metadata': meta
                        })
                    except Exception as e:
                        # Only print the exception type and a short message, never the exception object itself if it is not a string
                        msg = str(e)
                        if not isinstance(msg, str) or len(msg) > 200:
                            msg = f"{type(e).__name__} (see logs)"
                        print(f"[SERVER] file decryption failed for {file_id}: {type(e).__name__}: {msg}")
                        self.outbox.put({'type': 'file_error', 'file_id': file_id, 'error': msg})
        elif msg.get('type') == 'file_offer':
            # Pass file offer to client for approval
            self.outbox.put({
                'type': 'file_offer',
                'from_client': msg.get('from_client', peer_id),
                'file_id': msg.get('file_id'),
                'filename': msg.get('filename'),
                'size': msg.get('size'),
                'from_server': peer_id
            })
        elif msg.get('type') == 'file_offer_response':
            # Handle response to file offer
            file_id = msg.get('file_id')
            accepted = msg.get('accepted', False)
            print(f"[SERVER-DEBUG] Received file_offer_response: file_id={file_id}, accepted={accepted}")
            if hasattr(self, 'pending_file_offers') and file_id in self.pending_file_offers:
                offer = self.pending_file_offers.pop(file_id)
                print(f"[SERVER-DEBUG] Found pending offer for {file_id}, proceeding with transfer")
                if accepted:
                    # Proceed with file transfer (original send_file logic)
                    address = offer['address']
                    port = offer['port']
                    filepath = offer['filepath']
                    meta = offer['meta']
                    print(f"[SERVER-DEBUG] Starting file transfer: {filepath} to {address}")
                    if not os.path.exists('media'):
                        os.makedirs('media')
                    enc_path = os.path.join('media', f'{file_id}.enc')
                    key, nonce = media_utils.encrypt_file(filepath, enc_path)
                    # Encrypt AES key+nonce with recipient's RSA public key
                    peer_key = self.federation.known_servers.get(address)
                    if not peer_key:
                        self.outbox.put({'type': 'error', 'message': f'No public key for {address}. Cannot send file.'})
                        return
                    import encryption_utils as enc
                    key_nonce = key + nonce
                    print(f"[SERVER-DEBUG] RSA encrypting key_nonce: len={len(key_nonce)} bytes")
                    try:
                        encrypted_key_nonce = enc.rsa_encrypt(peer_key, key_nonce)
                        print(f"[SERVER-DEBUG] RSA encryption successful: encrypted_len={len(encrypted_key_nonce)} bytes")
                    except Exception as e:
                        import traceback
                        print(f"[SERVER] file_key RSA encryption failed: {type(e).__name__}: {e}")
                        print(f"[SERVER-DEBUG] Key size: {len(key)} bytes, Nonce size: {len(nonce)} bytes")
                        traceback.print_exc()
                        self.outbox.put({'type': 'error', 'message': f'RSA encryption failed for file_key: {e}'})
                        return
                    # Send file_key message (small, RSA-encrypted key+nonce only)
                    file_key_msg = {
                        'type': 'file_key',
                        'file_id': file_id,
                        'data': encrypted_key_nonce.hex()
                    }
                    self.federation.send_message(address, port, file_key_msg, plaintext=True)
                    # Send file_metadata (plaintext)
                    meta_msg = {
                        'type': 'file_metadata',
                        'from_client': self.client_id,
                        'file_id': file_id,
                        'metadata': meta
                    }
                    self.federation.send_message(address, port, meta_msg, plaintext=True)
                    # Send file in 99MB chunks (plaintext, already AES-encrypted)
                    chunk_size = 99 * 1024 * 1024
                    with open(enc_path, 'rb') as f:
                        idx = 0
                        while True:
                            chunk = f.read(chunk_size)
                            if not chunk:
                                break
                            chunk_msg = {
                                'type': 'file_chunk',
                                'file_id': file_id,
                                'chunk_idx': idx,
                                'data': chunk.hex()
                            }
                            self.federation.send_message(address, port, chunk_msg, plaintext=True)
                            idx += 1
                    self.outbox.put({'type': 'info', 'message': f'Sent file {filepath} to {address} as {file_id}.'})
                else:
                    self.outbox.put({'type': 'info', 'message': f'File offer declined by recipient.'})
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
                    address = target
                    try:
                        port = int(target.split(':')[1])
                        self.federation.send_message(address, port, msg)
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
            address = args.strip()
            if ':' in address:
                host, port = address.split(':')
                try:
                    port = int(port)
                    self.federation.send_contact_request(address, port)
                except Exception as e:
                    print(f"[SERVER] contact_request error: {e}")
        elif command == 'approve_contact_request':
            parts = args.split(' ', 1)
            if len(parts) == 2:
                address, request_id = parts
                self.federation.approve_contact_request(address, request_id)
        elif command == 'reject_contact_request':
            parts = args.split(' ', 1)
            if len(parts) == 2:
                address, request_id = parts
                self.federation.reject_contact_request(address, request_id)
        elif command == 'send_file':
            parts = args.split(' ', 1)
            if len(parts) == 2:
                target, filepath = parts
                if ':' in target and os.path.exists(filepath):
                    address = target  # full 'host:port'
                    port = int(target.split(':')[1])
                    file_id = os.path.basename(filepath) + '-' + secrets.token_hex(8)
                    meta = media_utils.generate_file_metadata(filepath)
                    meta['orig_filename'] = os.path.basename(filepath)
                    meta['file_id'] = file_id
                    # Send file_offer message and store pending offer
                    if not hasattr(self, 'pending_file_offers'):
                        self.pending_file_offers = {}
                    self.pending_file_offers[file_id] = {
                        'address': address, 'port': port, 'filepath': filepath, 'meta': meta
                    }
                    file_offer_msg = {
                        'type': 'file_offer',
                        'from_client': self.client_id,
                        'file_id': file_id,
                        'filename': meta['orig_filename'],
                        'size': meta['size']
                    }
                    self.federation.send_message(address, port, file_offer_msg, plaintext=True)
                    self.outbox.put({'type': 'info', 'message': f'File offer sent to {address}: {meta["orig_filename"]}'})
        elif command == 'file_offer_response':
            # args: address file_id accept/decline
            print(f"[SERVER-DEBUG] Entering file_offer_response command handler with args: {args}")
            # Split by space, but handle file_id that might contain spaces
            parts = args.split(' ')
            if len(parts) >= 3:
                address = parts[0]
                response = parts[-1]  # Last part is accept/decline
                file_id = ' '.join(parts[1:-1])  # Everything in between is the file_id
                port = int(address.split(':')[1])
                accepted = response.lower() == 'accept'
                
                # Send response to the other server
                msg = {
                    'type': 'file_offer_response',
                    'file_id': file_id,
                    'accepted': accepted
                }
                print(f"[SERVER-DEBUG] About to send file_offer_response: {msg}")
                self.federation.send_message(address, port, msg, plaintext=True)
                print(f"[SERVER-DEBUG] Sent file_offer_response to {address}: file_id={file_id}, accepted={accepted}")
            else:
                print(f"[SERVER-DEBUG] file_offer_response command has wrong number of parts: {len(parts)}")
        else:
            self.outbox.put({'type': 'info', 'message': f'Unknown command: {command} {args}'})

    def get_contacts(self):
        return self.federation.get_known_contacts()

    def stop(self):
        self.federation.stop()
        print("[SERVER] Backend stopped.")

    def get_public_key(self, address):
        key = self.federation.known_servers.get(address)
        if key:
            return enc.serialize_public_key(key)
        return None

def run_server(client_id):
    print(f"[SERVER] run_server called for client_id: {client_id}")
    # No-op for now; real server logic can be added here 