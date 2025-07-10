import sys
import os
import json
import threading
from PyQt6.QtWidgets import (
    QApplication, QWidget, QListWidget, QTextEdit, QLineEdit, QPushButton, QVBoxLayout, QHBoxLayout, QListWidgetItem, QMessageBox, QInputDialog, QMenu, QFileDialog, QTextBrowser
)
from PyQt6.QtCore import Qt, QTimer, QRect, QCoreApplication, QUrl
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet, InvalidToken
import base64
import getpass
import os
import secrets
import mimetypes
from PyQt6.QtGui import QDesktopServices
from room_client import RoomClient

class PyQtFederatedClient(QWidget):
    def save_joined_rooms(self):
        # Save the list of joined room IDs
        try:
            with open(self.rooms_file, 'w') as f:
                json.dump({'rooms': list(self.room_client.rooms.keys())}, f)
        except Exception as e:
            print(f"[CLIENT-DEBUG] Failed to save joined rooms: {e}")

    def load_joined_rooms(self):
        # Load and auto-join rooms from file
        try:
            if os.path.exists(self.rooms_file):
                with open(self.rooms_file, 'r') as f:
                    data = json.load(f)
                    for room_id in data.get('rooms', []):
                        self.room_client.join_room(room_id)
                        # Load history from disk into memory
                        self.room_client.room_histories[room_id] = self.load_room_history(room_id)
        except Exception as e:
            print(f"[CLIENT-DEBUG] Failed to load joined rooms: {e}")

    def __init__(self, backend, client_id=None):
        # RoomClient integration (must be first!)
        self.backend = backend
        self.client_id = client_id or backend.client_id
        self.room_client = RoomClient(
            user_id=self.client_id,
            send_func=self.send_room_command
        )
        self.room_client.set_on_room_update(self.on_room_update)
        self.room_client.set_on_room_message(self.on_room_message)
        self.room_client.set_on_file_offer(self.on_room_file_offer)
        super().__init__()
        self.setWindowTitle(f"Federated Chat Client (PyQt6) - {self.client_id}")
        self.resize(700, 500)
        self.contacts = {}
        self.removed_contacts = set()  # Track manually removed contacts
        self.active_chats = {}
        self.current_server = None
        self.unread_counts = {}
        self.pending_contact_key_approval = set()
        self.automated_message_sent = set()
        self.contacts_file = f'contacts_{self.client_id}.json'
        self.rooms_file = f'rooms_{self.client_id}.json'  # For room persistence
        self.salt_file = "chat_salt.bin"
        self.salt = self.load_or_create_salt()
        # Center the window before showing password prompt
        self.center_on_screen()
        self.key = self.prompt_for_password_and_derive_key()
        self.load_contacts()
        self.load_joined_rooms()  # Load and auto-join rooms
        self.load_all_chat_histories()
        self.clear_old_html_messages() # Call the new method here
        self.init_ui()
        self.poll_timer = QTimer()
        self.poll_timer.timeout.connect(self.poll_backend)
        self.poll_timer.start(100)
        # Center the main window after UI setup
        self.center_on_screen()

    def load_or_create_salt(self):
        if os.path.exists(self.salt_file):
            with open(self.salt_file, 'rb') as f:
                return f.read()
        salt = secrets.token_bytes(16)
        with open(self.salt_file, 'wb') as f:
            f.write(salt)
        return salt

    def prompt_for_password_and_derive_key(self):
        while True:
            # Center the dialog
            self.center_on_screen()
            password, ok = QInputDialog.getText(self, "Password", "Enter password to unlock chat history:", QLineEdit.EchoMode.Password)
            if not ok or not password:
                QMessageBox.critical(self, "Error", "Password required to unlock chat history.")
                sys.exit(1)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=self.salt,
                iterations=390000,
                backend=default_backend()
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            # Try to decrypt a known file (if exists) to verify password
            try:
                if os.path.exists("chat_test.enc"):
                    with open("chat_test.enc", "rb") as f:
                        Fernet(key).decrypt(f.read())
                else:
                    # Save a test file for future verification
                    with open("chat_test.enc", "wb") as f:
                        f.write(Fernet(key).encrypt(b"test"))
                return key
            except InvalidToken:
                QMessageBox.critical(self, "Error", "Incorrect password. Please try again.")

    def get_chat_history_file(self, address):
        return f"chat_{address.replace(':', '_')}.enc"

    def save_chat_history(self, address):
        file = self.get_chat_history_file(address)
        messages = self.active_chats.get(address, [])
        try:
            data = json.dumps(messages).encode()
            encrypted = Fernet(self.key).encrypt(data)
            with open(file, "wb") as f:
                f.write(encrypted)
        except Exception as e:
            print(f"[CLIENT-DEBUG] Failed to save chat history for {address}: {e}")

    def load_chat_history(self, address):
        file = self.get_chat_history_file(address)
        if not os.path.exists(file):
            return []
        try:
            with open(file, "rb") as f:
                encrypted = f.read()
            data = Fernet(self.key).decrypt(encrypted)
            return json.loads(data.decode())
        except Exception as e:
            print(f"[CLIENT-DEBUG] Failed to load chat history for {address}: {e}")
            return []

    def get_room_history_file(self, room_id):
        return f"room_{room_id}.enc"

    def save_room_history(self, room_id):
        file = self.get_room_history_file(room_id)
        messages = self.room_client.get_room_history(room_id)
        try:
            data = json.dumps(messages).encode()
            encrypted = Fernet(self.key).encrypt(data)
            with open(file, "wb") as f:
                f.write(encrypted)
        except Exception as e:
            print(f"[CLIENT-DEBUG] Failed to save room history for {room_id}: {e}")

    def load_room_history(self, room_id):
        file = self.get_room_history_file(room_id)
        if not os.path.exists(file):
            return []
        try:
            with open(file, "rb") as f:
                encrypted = f.read()
            data = Fernet(self.key).decrypt(encrypted)
            return json.loads(data.decode())
        except Exception as e:
            print(f"[CLIENT-DEBUG] Failed to load room history for {room_id}: {e}")
            return []

    def clear_old_html_messages(self):
        """Clear old chat history that contains HTML Accept/Decline messages"""
        for address in list(self.active_chats.keys()):
            messages = self.active_chats[address]
            # Filter out messages that contain HTML Accept/Decline links
            filtered_messages = []
            for msg in messages:
                if isinstance(msg, tuple) and len(msg) == 2 and msg[0] == 'System':
                    message = msg[1]
                    if isinstance(message, str) and ('accept://' in message or 'decline://' in message):
                        # Skip old HTML Accept/Decline messages
                        continue
                filtered_messages.append(msg)
            
            if len(filtered_messages) != len(messages):
                print(f"[CLIENT-DEBUG] Cleared {len(messages) - len(filtered_messages)} old HTML messages from {address}")
                self.active_chats[address] = filtered_messages
                self.save_chat_history(address)

    def load_all_chat_histories(self):
        self.active_chats = {}
        for address in self.contacts:
            self.active_chats[address] = self.load_chat_history(address)

    def init_ui(self):
        main_layout = QHBoxLayout(self)
        # Menu bar
        self.menu_bar = QMenu(self)
        self.menu = QMenu("Menu", self)
        self.menu_bar.addAction(self.menu.menuAction())
        self.menu.addAction("Add Contact", self.on_add_contact)
        self.menu.addAction("Create Room", self.on_create_room)
        self.menu.addAction("Join Room", self.on_join_room)
        self.menu.addAction("Lock", self.lock_ui)
        self.menuBarWidget = QPushButton("☰ Menu")
        self.menuBarWidget.setMenu(self.menu)
        main_layout.addWidget(self.menuBarWidget, alignment=Qt.AlignmentFlag.AlignTop)
        # Left panel (vertical layout)
        left_panel = QVBoxLayout()
        self.username_label = QPushButton(f"Username: {self.client_id}")
        self.username_label.setEnabled(False)
        left_panel.addWidget(self.username_label)
        # Contact list
        self.contact_list = QListWidget()
        self.contact_list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.contact_list.customContextMenuRequested.connect(self.on_right_click_contact)
        self.contact_list.itemDoubleClicked.connect(self.on_double_click_contact)
        self.contact_list.currentItemChanged.connect(self.on_select_contact)
        left_panel.addWidget(self.contact_list, 1)
        main_layout.addLayout(left_panel, 2)
        # Chat area
        chat_layout = QVBoxLayout()
        # Chat display
        self.chat_display = QTextBrowser()
        self.chat_display.setOpenExternalLinks(False)  # Prevent default link handling
        self.chat_display.anchorClicked.connect(self.handle_chat_link)  # Use our custom handler
        self.chat_display.setStyleSheet("""
            QTextBrowser {
                border: 1px solid #dee2e6;
                border-radius: 5px;
                padding: 10px;
                font-family: 'Segoe UI', Arial, sans-serif;
                font-size: 12px;
                line-height: 1.4;
            }
        """)
        chat_layout.addWidget(self.chat_display, 8)
        # Message entry
        entry_layout = QHBoxLayout()
        self.message_entry = QLineEdit()
        self.message_entry.returnPressed.connect(self.on_send_message)
        entry_layout.addWidget(self.message_entry, 8)
        self.send_button = QPushButton("Send")
        self.send_button.clicked.connect(self.on_send_message)
        entry_layout.addWidget(self.send_button, 2)
        # File attachment button
        self.attach_button = QPushButton("📎")
        self.attach_button.setToolTip("Attach file")
        self.attach_button.clicked.connect(self.on_attach_file)
        entry_layout.addWidget(self.attach_button, 1)
        chat_layout.addLayout(entry_layout)
        main_layout.addLayout(chat_layout, 8)
        self.setLayout(main_layout)
        self.refresh_contacts_from_backend()

    def load_contacts(self):
        if os.path.exists(self.contacts_file):
            try:
                with open(self.contacts_file, 'r') as f:
                    data = json.load(f)
                    self.contacts = data.get('contacts', {})
                    self.removed_contacts = set(data.get('removed_contacts', [])) # Load removed contacts
            except Exception:
                self.contacts = {}
                self.removed_contacts = set()
        else:
            self.contacts = {}
            self.removed_contacts = set()

    def save_contacts(self):
        try:
            with open(self.contacts_file, 'w') as f:
                json.dump({'contacts': self.contacts, 'removed_contacts': list(self.removed_contacts)}, f)
        except Exception:
            pass

    def update_contact(self, address, username):
        if not address or not username:
            return
        self.contacts[address] = username
        self.save_contacts()
        self.update_contact_list()

    def update_contact_list(self):
        # Preserve current selection
        prev_address = self.current_server
        self.contact_list.blockSignals(True)
        self.contact_list.clear()
        # Combine contacts and rooms for display
        addresses = sorted(self.contacts.keys(), key=lambda x: self.contacts[x])
        room_ids = sorted(self.room_client.rooms.keys())
        display_items = []
        for room_id in room_ids:
            room = self.room_client.rooms[room_id]
            name = room.get('name', room_id)
            display = f"# {name} [{room_id[:6]}]"
            display_items.append((room_id, display, True))  # True = is_room
        for address, username in sorted(self.contacts.items(), key=lambda x: x[1]):
            display = f"{username} ({address})" if username != address else address
            display_items.append((address, display, False))  # False = is_room
        for idx, (addr, display, is_room) in enumerate(display_items):
            unread = self.unread_counts.get(addr, 0)
            if unread > 0:
                item = QListWidgetItem(f"{display} [{unread}]")
            else:
                item = QListWidgetItem(f"{display}")
            item.setData(Qt.ItemDataRole.UserRole, {'is_room': is_room, 'id': addr})
            self.contact_list.addItem(item)
        # Restore previous selection if possible
        all_ids = [x[0] for x in display_items]
        if prev_address in all_ids:
            idx = all_ids.index(prev_address)
            self.contact_list.setCurrentRow(idx)
        self.contact_list.blockSignals(False)

    def refresh_contacts_from_backend(self):
        prev_address = self.current_server
        try:
            contacts = self.backend.get_contacts()
            for addr in contacts:
                # Don't reload contacts that have been manually removed
                if addr not in self.removed_contacts and addr not in self.contacts:
                    self.contacts[addr] = addr
            self.update_contact_list()
        except Exception as e:
            print(f"[CLIENT-DEBUG] refresh_contacts_from_backend error: {e}")
        # Restore previous selection if possible
        addresses = sorted(self.contacts.keys(), key=lambda x: self.contacts[x])
        if prev_address in addresses:
            idx = addresses.index(prev_address)
            self.contact_list.setCurrentRow(idx)

    def poll_backend(self):
        try:
            msg = self.backend.get_message(timeout=0.01)
            if not msg:
                return
            print(f"[CLIENT-DEBUG] poll_backend received: {msg}")
            msg_type = msg.get('type')
            print(f"[CLIENT-DEBUG] Message type: {msg_type}")
            # Handle federated room join response
            if msg_type == 'federated_room_join_response':
                if msg.get('success') and 'room' in msg:
                    room = msg['room']
                    self.room_client.rooms[room['room_id']] = room
                    # Deduplicate and save history
                    seen = set()
                    deduped = []
                    for m in room.get('history', []):
                        mid = m.get('msg_id')
                        if mid and mid not in seen:
                            deduped.append(m)
                            seen.add(mid)
                    self.room_client.room_histories[room['room_id']] = deduped
                    self.save_room_history(room['room_id'])
                    self.save_joined_rooms()  # <-- Ensure joined rooms are persisted
                    # (Removed: do not add all room members as contacts)
                    self.update_contact_list()
                    self.display_room_chat(room['room_id'])
                    QMessageBox.information(self, "Room Joined", f"Successfully joined room: {room.get('name', room['room_id'])}")
                else:
                    QMessageBox.warning(self, "Join Failed", msg.get('error', 'Unknown error'))
                return
            # Room protocol message routing
            if msg_type in [
                'room_create_success', 'room_create_error', 'room_join_success', 'room_join_error',
                'room_leave_success', 'room_message', 'room_history_response', 'room_file_offer',
                # Add more room protocol types as needed
            ]:
                self.room_client.handle_incoming_room_message(msg)
                return
            if msg_type == 'chat_message':
                address = msg.get('from_server') or msg.get('address')
                from_client = msg.get('from_client', address)
                message = msg.get('message')
                if address not in self.active_chats:
                    self.active_chats[address] = self.load_chat_history(address)
                self.active_chats[address].append((from_client, message))
                self.save_chat_history(address)
                # Only update chat display if the message is for the currently selected contact
                if self.current_server == address:
                    self.display_chat(address)
                else:
                    self.unread_counts[address] = self.unread_counts.get(address, 0) + 1
                    self.update_contact_list()
                if address not in self.contacts and message.endswith('has accepted your chat request.'):
                    public_key = None
                    if hasattr(self.backend, 'get_public_key'):
                        public_key = self.backend.get_public_key(address)
                    if public_key:
                        self.handle_key_approval({
                            'server_addr': address,
                            'public_key': public_key,
                            'reason': 'new',
                            'force_popup': True
                        })
            elif msg_type == 'key_approval':
                self.handle_key_approval(msg)
            elif msg_type == 'contact_request':
                self.handle_incoming_contact_request(msg)
            elif msg_type == 'add_contact':
                address = msg.get('address')
                username = msg.get('username', address)
                print(f"[CLIENT-DEBUG] add_contact event: address={address}, username={username}")
                is_new = address not in self.contacts
                self.update_contact(address, username)
                self.refresh_contacts_from_backend()
                if is_new and username != self.client_id and address not in self.automated_message_sent and address not in self.removed_contacts:
                    auto_msg = f"{self.client_id} has accepted your chat request."
                    print(f"[CLIENT-DEBUG] Sending automated acceptance message to {address}: {auto_msg}")
                    self.backend.send_command('chat_message', f'{address} {auto_msg}')
                    self.automated_message_sent.add(address)
            elif msg_type == 'info':
                print(f"[CLIENT-DEBUG] info event: {msg.get('message')}")
                self.refresh_contacts_from_backend()
            elif msg_type == 'file_metadata':
                address = msg.get('from_server') or msg.get('from_client') or msg.get('address')
                file_id = msg.get('file_id')
                meta = msg.get('metadata', {})
                print(f"[CLIENT-DEBUG] Received file_metadata for file_id: {file_id}")
                # Progress dialog is already shown when accepting the file offer
                # No need to add chat messages anymore
            elif msg_type == 'file_complete':
                file_id = msg.get('file_id')
                decrypted_path = msg.get('decrypted_path')
                orig_filename = msg.get('orig_filename')
                metadata = msg.get('metadata', {})
                print(f"[CLIENT-DEBUG] file_complete: file_id={file_id}, dec_path={decrypted_path}")
                
                # Find the address by looking up the file_id in existing chat history
                address = None
                for addr, messages in self.active_chats.items():
                    for msg_tuple in messages:
                        if (isinstance(msg_tuple, tuple) and len(msg_tuple) > 2 and 
                            isinstance(msg_tuple[2], dict) and 
                            msg_tuple[2].get('file_id') == file_id):
                            address = addr
                            break
                    if address:
                        break
                
                if not address:
                    print(f"[CLIENT-DEBUG] Warning: Could not find address for file_id {file_id}")
                    # Try to use current_server as fallback
                    address = self.current_server
                    if not address:
                        print(f"[CLIENT-DEBUG] No current_server either, cannot process file_complete")
                        return
                
                print(f"[CLIENT-DEBUG] Found address for file {file_id}: {address}")
                
                # Close progress dialog and show completion popup
                self.close_file_progress_dialog(file_id)
                
                # Add the completed file to chat history so it can be displayed inline
                if address and decrypted_path and os.path.exists(decrypted_path):
                    if address not in self.active_chats:
                        self.active_chats[address] = self.load_chat_history(address)
                    
                    # Add the file to chat history with 'ready' status
                    self.active_chats[address].append((address, f'[File: {orig_filename}]', {
                        'file_id': file_id,
                        'path': decrypted_path,
                        'meta': metadata,
                        'status': 'ready'
                    }))
                    self.save_chat_history(address)
                    
                    # Update the chat display if this is the current conversation
                    if self.current_server == address:
                        self.display_chat(address)
                
                # Show completion popup
                QMessageBox.information(self, "Download Complete", "File download has completed successfully!")
            elif msg_type == 'file_offer':
                address = msg.get('from_server') or msg.get('from_client') or msg.get('address')
                file_id = msg.get('file_id')
                filename = msg.get('filename')
                from_client = msg.get('from_client', address)
                size = msg.get('size', 0)
                
                # Show file offer popup with Accept/Decline buttons
                size_mb = size / (1024 * 1024) if size > 0 else 0
                text = f"{from_client} wants to send:\n\nFile: {filename}\nSize: {size_mb:.1f} MB\n\nAccept this file transfer?"
                
                reply = QMessageBox.question(
                    self, 
                    "File Transfer Request", 
                    text, 
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No
                )
                
                if reply == QMessageBox.StandardButton.Yes:
                    # Accept the file transfer
                    print(f"[CLIENT-DEBUG] Accepting file transfer: {file_id}")
                    self.backend.send_command('file_offer_response', f'{address} {file_id} accept')

                    # Add a placeholder to chat history for this file transfer
                    if address not in self.active_chats:
                        self.active_chats[address] = self.load_chat_history(address)
                    self.active_chats[address].append((address, f'[File: {filename}] (Receiving...)', {
                        'file_id': file_id,
                        'meta': {'orig_filename': filename},
                        'status': 'receiving'
                    }))
                    self.save_chat_history(address)
                    if self.current_server == address:
                        self.display_chat(address)

                    # Show progress dialog for download (non-modal)
                    self.show_file_progress_dialog(address, file_id, filename, size)
                else:
                    # Decline the file transfer
                    print(f"[CLIENT-DEBUG] Declining file transfer: {file_id}")
                    self.backend.send_command('file_offer_response', f'{address} {file_id} decline')
                    
                    # Show decline confirmation
                    QMessageBox.information(self, "File Transfer Declined", f"File transfer for {filename} was declined.")
            elif msg_type == 'file_chunk':
                file_id = msg.get('file_id')
                chunk_num = msg.get('chunk_num')
                total_chunks = msg.get('total_chunks')
                print(f"[CLIENT-DEBUG] Received file_chunk {chunk_num}/{total_chunks} for file_id: {file_id}")
                
                # Update progress dialog with actual progress
                if hasattr(self, 'file_progress_dialogs'):
                    print(f"[CLIENT-DEBUG] Progress dialogs: {list(self.file_progress_dialogs.keys())}")
                    if file_id in self.file_progress_dialogs:
                        progress = self.file_progress_dialogs[file_id]
                        if total_chunks > 0:
                            progress_value = int((chunk_num / total_chunks) * 100)
                            progress.setValue(progress_value)
                            print(f"[CLIENT-DEBUG] Updated progress to {progress_value}% for file {file_id}")
                        else:
                            print(f"[CLIENT-DEBUG] total_chunks is 0 or invalid: {total_chunks}")
                    else:
                        print(f"[CLIENT-DEBUG] No progress dialog found for file_id: {file_id}")
                else:
                    print(f"[CLIENT-DEBUG] No file_progress_dialogs attribute found")
                
                # Progress is handled by the progress dialog, no need for chat messages
            elif msg_type == 'file_error':
                file_id = msg.get('file_id')
                error = msg.get('error', 'Unknown error')
                print(f"[CLIENT-DEBUG] file_error: file_id={file_id}, error={error}")
                QMessageBox.critical(self, "File Transfer Error", f"File transfer failed for file ID:\n{file_id}\n\nError: {error}")
            else:
                print(f"[CLIENT-DEBUG] Unhandled message type: {msg_type}")
        except Exception as e:
            print(f"[CLIENT-DEBUG] Exception in poll_backend: {e}")

    def handle_key_approval(self, msg):
        address = msg.get('server_addr')
        public_key = msg.get('public_key')
        reason = msg.get('reason', 'new')
        force_popup = msg.get('force_popup', False)
        # Only show the key approval popup for existing contacts (key change), unless forced
        if not force_popup and address not in self.contacts:
            # Suppress popup for new contact requests unless forced
            return
        text = f"Key {reason} for {address}.\nPublic Key (PEM):\n{public_key[:60]}...\nApprove?"
        reply = QMessageBox.question(self, "Key Approval", text, QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            self.backend.send_command('approve_key', f'{address} {public_key}')
            # Add to contacts after approval
            self.update_contact(address, address)
            self.refresh_contacts_from_backend()
        else:
            QMessageBox.warning(self, "Key Rejected", f"Key for {address} was not approved.")

    def on_add_contact(self):
        address, ok = QInputDialog.getText(self, "Add Contact", "Enter server address (host:port):")
        if not ok or not address:
            return
        # Send contact request via backend
        self.backend.send_command('contact_request', address)
        QMessageBox.information(self, "Contact Request", f"Contact request sent to {address}. Awaiting approval.")

    def on_create_room(self):
        name, ok = QInputDialog.getText(self, "Create Room", "Enter room name:")
        if not ok or not name:
            return
        is_private, ok = QInputDialog.getItem(self, "Room Privacy", "Select room type:", ["Public", "Private"], 0, False)
        if not ok:
            return
        password = None
        if is_private == "Private":
            password, ok = QInputDialog.getText(self, "Room Password", "Set a password for the room:", QLineEdit.EchoMode.Password)
            if not ok or not password:
                return
        self.room_client.create_room(name, is_private == "Private", password)

    def on_join_room(self):
        room_id, ok = QInputDialog.getText(self, "Join Room", "Enter room ID:")
        if not ok or not room_id:
            return
        server_addr, ok = QInputDialog.getText(self, "Join Room", "Enter server address (host:port) of a member:")
        if not ok or not server_addr:
            return
        password = None
        # Check if the room is private (if known)
        room = self.room_client.get_room(room_id)
        if room and room.get('is_private'):
            password, ok = QInputDialog.getText(self, "Room Password", "Enter room password:", QLineEdit.EchoMode.Password)
            if not ok or not password:
                return
        # Get our own server address
        joiner_server = None
        if hasattr(self.backend, 'host') and hasattr(self.backend, 'port'):
            joiner_server = f"{self.backend.host}:{self.backend.port}"
        # Send federated join request to the specified server
        join_request = {
            'type': 'federated_room_join_request',
            'room_id': room_id,
            'password': password,
            'joiner_id': self.client_id,
            'joiner_server': joiner_server
        }
        try:
            host, port = server_addr.split(':')
            port = int(port)
            # Use backend's federation to send the message
            if hasattr(self.backend, 'federation'):
                self.backend.federation.send_message(server_addr, port, join_request, plaintext=True)
            else:
                QMessageBox.warning(self, "Federation Error", "Federation not available in backend.")
        except Exception as e:
            QMessageBox.warning(self, "Federation Error", f"Failed to send join request: {e}")

    def on_select_contact(self, current, previous):
        if current is None:
            return
        idx = self.contact_list.currentRow()
        item = self.contact_list.item(idx)
        if not item:
            return
        data = item.data(Qt.ItemDataRole.UserRole)
        if data and data.get('is_room'):
            self.current_server = data['id']
            self.display_room_chat(data['id'])
        else:
            address = list(sorted(self.contacts.keys(), key=lambda x: self.contacts[x]))[idx - len(self.room_client.rooms)] if idx >= len(self.room_client.rooms) else None
            self.current_server = address
            self.unread_counts[address] = 0
            self.update_contact_list()
            if address not in self.active_chats:
                self.active_chats[address] = self.load_chat_history(address)
            self.display_chat(address)

    def display_chat(self, address):
        self.chat_display.clear()
        self.file_entry_map = {}  # Map both full display text and filename to file path
        messages = self.active_chats.get(address, [])
        for msg in messages:
            if isinstance(msg, tuple) and len(msg) > 2 and isinstance(msg[2], dict) and msg[2].get('status') == 'ready':
                # File ready to open
                file_info = msg[2]
                path = file_info.get('path')
                saved_filename = os.path.basename(path) if path else '(unknown)'
                file_exists = os.path.exists(path) if path else False
                sender = msg[0]
                if sender == self.client_id:
                    display_name = "You"
                elif sender in self.contacts.values():
                    display_name = sender
                elif sender in self.contacts:
                    display_name = self.contacts.get(sender, sender)
                else:
                    display_name = sender
                
                # Compose display text for the file entry
                plain_display = f'{display_name}: 📎 {saved_filename}'
                file_display = f'<span style="color: #007bff; text-decoration: underline; cursor: pointer;"><b>{display_name}:</b> 📎 {saved_filename}</span>' if file_exists else f'<span style="color: #6c757d; text-decoration: line-through;"><b>{display_name}:</b> 📎 {saved_filename} (file not found)</span>'
                self.chat_display.append(file_display)
                if file_exists:
                    # Store mapping from both full display text and filename to file path
                    self.file_entry_map[plain_display] = os.path.abspath(path)
                    self.file_entry_map[saved_filename] = os.path.abspath(path)
            else:
                sender, message = msg[:2]
                if sender == 'System':
                    if isinstance(message, str):
                        print(f"[CLIENT-DEBUG] Appending System message to chat: {message}")
                        self.chat_display.append(message)
                    else:
                        self.chat_display.append(str(message))
                else:
                    if sender == self.client_id:
                        display_name = "You"
                    elif sender in self.contacts.values():
                        display_name = sender
                    elif sender in self.contacts:
                        display_name = self.contacts.get(sender, sender)
                    else:
                        display_name = sender
                    self.chat_display.append(f"<b>{display_name}:</b> {message}")

        # Install event filter for click-to-open
        self.chat_display.viewport().installEventFilter(self)

    def on_send_message(self):
        message = self.message_entry.text().strip()
        print(f"[CLIENT-DEBUG] on_send_message called: message='{message}', current_server='{self.current_server}'")
        if not message or not self.current_server:
            print("[CLIENT-DEBUG] on_send_message: No message or no contact selected.")
            return
        address = self.current_server
        # Check if this is a room
        if address in self.room_client.rooms:
            # Send to room, but do NOT add to history immediately (wait for server broadcast)
            msg_id = secrets.token_hex(8)
            self.room_client.send_room_message(address, {'sender': self.client_id, 'text': message, 'msg_id': msg_id})
            self.message_entry.clear()
            return
        # Normal contact message
        if address not in self.active_chats:
            self.active_chats[address] = self.load_chat_history(address)
        self.active_chats[address].append((self.client_id, message))
        self.save_chat_history(address)
        self.display_chat(address)
        self.message_entry.clear()
        if address:
            print(f"[CLIENT-DEBUG] Sending message to {address}: {message}")
            self.backend.send_command('chat_message', f'{address} {message}')

    def on_double_click_contact(self, item):
        idx = self.contact_list.currentRow()
        address = list(sorted(self.contacts.keys(), key=lambda x: self.contacts[x]))[idx]
        self.backend.send_command('connection_request', address)
        QMessageBox.information(self, "Connection", f"Connection request sent to {address}")

    def on_right_click_contact(self, pos):
        idx = self.contact_list.indexAt(pos).row()
        if idx < 0:
            return
        item = self.contact_list.item(idx)
        data = item.data(Qt.ItemDataRole.UserRole)
        if data and data.get('is_room'):
            room_id = data['id']
            menu = QMenu()
            leave_action = menu.addAction(f"Leave Room {room_id}")
            action = menu.exec(self.contact_list.mapToGlobal(pos))
            if action == leave_action:
                self.room_client.leave_room(room_id)
        else:
            address = data['id'] if data else None
            menu = QMenu()
            remove_action = menu.addAction(f"Remove {address}")
            action = menu.exec(self.contact_list.mapToGlobal(pos))
            if action == remove_action:
                # Confirm removal
                reply = QMessageBox.question(
                    self, 
                    "Remove Contact", 
                    f"Are you sure you want to remove {address}?\nThis will also clear all chat history with this contact.",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No
                )
                if reply == QMessageBox.StandardButton.Yes:
                    # Remove from backend (if backend supports it)
                    try:
                        self.backend.send_command('remove_contact', address)
                    except:
                        pass  # Backend might not support this command yet
                    # Remove from local contacts
                    if address in self.contacts:
                        del self.contacts[address]
                    self.removed_contacts.add(address)  # Add to removed contacts set
                    self.save_contacts()
                    # Clear chat history for this contact
                    if address in self.active_chats:
                        del self.active_chats[address]
                    # Delete chat history file
                    chat_file = self.get_chat_history_file(address)
                    if os.path.exists(chat_file):
                        try:
                            os.remove(chat_file)
                            print(f"[CLIENT-DEBUG] Deleted chat history file: {chat_file}")
                        except Exception as e:
                            print(f"[CLIENT-DEBUG] Failed to delete chat history: {e}")
                    # Clear unread count
                    if address in self.unread_counts:
                        del self.unread_counts[address]
                    # Update UI
                    self.update_contact_list()
                    if self.current_server == address:
                        self.current_server = None
                        self.chat_display.clear()
                    QMessageBox.information(self, "Contact Removed", f"{address} has been removed and chat history cleared.")

    def handle_incoming_contact_request(self, msg):
        from_addr = msg.get('from_addr')
        request_id = msg.get('request_id')
        public_key = msg.get('public_key')
        key_is_new = from_addr not in self.contacts
        if key_is_new:
            self.pending_contact_key_approval.add(from_addr)
            text = (f"{from_addr} wants to add you as a contact.\n"
                    f"Their public key (PEM):\n{public_key[:60]}...\nApprove?")
        else:
            text = f"{from_addr} wants to add you as a contact. Approve?"
        reply = QMessageBox.question(self, "Contact Request", text, QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            if key_is_new:
                self.backend.send_command('approve_key', f'{from_addr} {public_key}')
            self.backend.send_command('approve_contact_request', f'{from_addr} {request_id}')
        else:
            self.backend.send_command('reject_contact_request', f'{from_addr} {request_id}')

    def lock_ui(self):
        # Disable all input and chat display
        self.chat_display.setReadOnly(True)
        self.message_entry.setEnabled(False)
        self.send_button.setEnabled(False)
        self.contact_list.setEnabled(False)
        self.menuBarWidget.setEnabled(False)
        self.username_label.setEnabled(False)
        # Overlay a solid color QWidget to obscure the window
        self.lock_overlay = QWidget(self)
        self.lock_overlay.setStyleSheet("background-color: #222;")
        self.lock_overlay.setGeometry(0, 0, self.width(), self.height())
        self.lock_overlay.setAutoFillBackground(True)
        self.lock_overlay.setWindowFlags(self.lock_overlay.windowFlags() | Qt.WindowType.SubWindow)
        self.lock_overlay.show()
        self.lock_overlay.raise_()
        self.lock_overlay.setFocus()
        # Show unlock dialog
        while True:
            password, ok = QInputDialog.getText(self, "Unlock", "Enter password to unlock:", QLineEdit.EchoMode.Password)
            if not ok or not password:
                QMessageBox.critical(self, "Error", "Password required to unlock.")
                continue
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=self.salt,
                iterations=390000,
                backend=default_backend()
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            try:
                # Try to decrypt the test file
                if os.path.exists("chat_test.enc"):
                    with open("chat_test.enc", "rb") as f:
                        Fernet(key).decrypt(f.read())
                # If successful, restore UI and set key
                self.key = key
                self.chat_display.setReadOnly(True)
                self.message_entry.setEnabled(True)
                self.send_button.setEnabled(True)
                self.contact_list.setEnabled(True)
                self.menuBarWidget.setEnabled(True)
                self.username_label.setEnabled(False)
                # Remove overlay
                self.lock_overlay.hide()
                self.lock_overlay.deleteLater()
                del self.lock_overlay
                break
            except InvalidToken:
                QMessageBox.critical(self, "Error", "Incorrect password. Please try again.")

    def on_attach_file(self):
        if not self.current_server:
            QMessageBox.warning(self, "No Contact Selected", "Please select a contact to send a file.")
            return
        file_dialog = QFileDialog(self)
        file_dialog.setFileMode(QFileDialog.FileMode.ExistingFile)
        if file_dialog.exec():
            file_paths = file_dialog.selectedFiles()
            if file_paths:
                filepath = file_paths[0]
                address = self.current_server
                self.backend.send_command('send_file', f'{address} {filepath}')
                QMessageBox.information(self, "File Sent", f"File sent to {address}: {os.path.basename(filepath)}")

    def center_on_screen(self):
        screen = QApplication.primaryScreen()
        if screen:
            screen_geometry = screen.availableGeometry()
            window_geometry = self.frameGeometry()
            center_point = screen_geometry.center()
            window_geometry.moveCenter(center_point)
            self.move(window_geometry.topLeft())

    def show_file_progress_dialog(self, address, file_id, filename, total_size):
        """Show a progress dialog for file transfer"""
        from PyQt6.QtWidgets import QProgressDialog
        from PyQt6.QtCore import Qt
        
        print(f"[CLIENT-DEBUG] show_file_progress_dialog called: file_id={file_id}, filename={filename}")
        
        # Store progress dialogs by file_id
        if not hasattr(self, 'file_progress_dialogs'):
            self.file_progress_dialogs = {}
        
        size_mb = total_size / (1024 * 1024) if total_size > 0 else 0
        progress = QProgressDialog(f"Downloading: {filename}\nSize: {size_mb:.1f} MB", "Cancel", 0, 100, self)
        progress.setWindowTitle("File Download Progress")
        progress.setWindowModality(Qt.WindowModality.NonModal)  # Non-modal so user can still use the app
        progress.setAutoClose(False)
        progress.setAutoReset(False)
        progress.setMinimumDuration(0)  # Show immediately
        progress.show()
        
        self.file_progress_dialogs[file_id] = progress
        print(f"[CLIENT-DEBUG] Progress dialog created and stored for file_id: {file_id}")
        print(f"[CLIENT-DEBUG] Current progress dialogs: {list(self.file_progress_dialogs.keys())}")
        
        # Start with 0% progress
        progress.setValue(0)
        
    def close_file_progress_dialog(self, file_id):
        """Close the progress dialog for a specific file"""
        if hasattr(self, 'file_progress_dialogs') and file_id in self.file_progress_dialogs:
            progress = self.file_progress_dialogs[file_id]
            progress.setValue(100)
            progress.close()
            del self.file_progress_dialogs[file_id]

    def handle_chat_link(self, url):
        """Handle clicks on links in the chat display and prevent navigation/blanking."""
        url_string = url.toString()
        print(f"[CLIENT-DEBUG] Link clicked: {url_string}")
        self.chat_display.setSource(QUrl())
        file_path = url.toLocalFile()
        if file_path:
            abs_file_path = os.path.abspath(os.path.normpath(file_path))
            print(f"[CLIENT-DEBUG] Absolute file path: {abs_file_path}")
            if os.path.exists(abs_file_path):
                print(f"[CLIENT-DEBUG] Opening file: {abs_file_path}")
                try:
                    QDesktopServices.openUrl(QUrl.fromLocalFile(abs_file_path))
                except Exception as e:
                    print(f"[CLIENT-DEBUG] Failed to open file: {e}")
                    QMessageBox.warning(self, "File Error", f"Could not open file: {os.path.basename(abs_file_path)}")
            else:
                print(f"[CLIENT-DEBUG] File not found: {abs_file_path}")
                QMessageBox.warning(self, "File Not Found", f"File not found: {os.path.basename(abs_file_path)}")
        else:
            print(f"[CLIENT-DEBUG] No file path found in link!")

    def eventFilter(self, obj, event):
        from PyQt6.QtCore import QEvent
        if obj == self.chat_display.viewport() and event.type() == QEvent.Type.MouseButtonRelease:
            print(f"[CLIENT-DEBUG] eventFilter: Mouse event {event.type()} at {event.position().toPoint()}")
            cursor = self.chat_display.cursorForPosition(event.position().toPoint())
            cursor.select(cursor.SelectionType.LineUnderCursor)
            selected_text = cursor.selectedText().strip()
            print(f"[CLIENT-DEBUG] eventFilter: Selected text: '{selected_text}'")
            # Try to match the selected text to a file entry by full display text or filename
            if selected_text in self.file_entry_map:
                file_path = self.file_entry_map[selected_text]
                print(f"[CLIENT-DEBUG] Clicked file entry: {file_path}")
                if os.path.exists(file_path):
                    QDesktopServices.openUrl(QUrl.fromLocalFile(file_path))
                else:
                    QMessageBox.warning(self, "File Not Found", f"File not found: {os.path.basename(file_path)}")
                return True
        return super().eventFilter(obj, event)

    def is_media_file(self, filepath):
        """Check if a file is an image or video"""
        if not filepath or not os.path.exists(filepath):
            return False
        
        mime_type, _ = mimetypes.guess_type(filepath)
        if mime_type:
            return mime_type.startswith(('image/', 'video/'))
        return False
    
    def get_media_display_html(self, filepath, filename, max_width=300, max_height=200):
        """Generate HTML for displaying media files inline"""
        if not self.is_media_file(filepath):
            return None
        
        mime_type, _ = mimetypes.guess_type(filepath)
        if not mime_type:
            return None
        
        # Convert file path to file:// URL for HTML display
        file_url = QUrl.fromLocalFile(filepath).toString()
        
        if mime_type.startswith('image/'):
            # Display image inline
            return f'<div style="margin: 5px 0;"><img src="{file_url}" style="max-width: {max_width}px; max-height: {max_height}px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);" alt="{filename}"><br><small style="color: inherit; opacity: 0.7;">{filename}</small></div>'
        
        elif mime_type.startswith('video/'):
            # Display video with thumbnail and play button
            # For now, show a video placeholder with filename
            # In a more advanced implementation, we could generate thumbnails
            return f'<div style="margin: 5px 0; padding: 10px; background: rgba(0,0,0,0.05); border-radius: 8px; border: 1px solid rgba(0,0,0,0.1);"><a href="file://{filepath}" style="text-decoration: none; color: #007bff;">🎬 {filename}</a><br><small style="color: inherit; opacity: 0.7;">Click to play video</small></div>'
        
        return None

    def send_room_command(self, msg: dict):
        """Send a room protocol message to the backend/server."""
        self.backend.send_command('room_protocol', msg)

    # --- RoomClient UI callback stubs ---
    def on_room_update(self, room_dict):
        print(f"[ROOM-DEBUG] Room update: {room_dict}")
        self.update_contact_list()
        self.save_joined_rooms()
        # --- Fix: update room history if present ---
        if 'room_id' in room_dict and 'history' in room_dict:
            room_id = room_dict['room_id']
            history = room_dict['history']
            # Deduplicate by msg_id
            seen = set()
            deduped = []
            for msg in history:
                mid = msg.get('msg_id')
                if mid and mid not in seen:
                    deduped.append(msg)
                    seen.add(mid)
            self.room_client.room_histories[room_id] = deduped
            self.save_room_history(room_id)
            if self.current_server == room_id:
                self.display_room_chat(room_id)

    def on_room_message(self, room_id, message_dict):
        print(f"[ROOM-CLIENT-DEBUG] on_room_message: room_id={room_id}, msg_id={message_dict.get('msg_id')}")
        # Only add message if msg_id is new (avoid duplicates)
        history = self.room_client.get_room_history(room_id)
        msg_ids = {msg.get('msg_id') for msg in history if isinstance(msg, dict)}
        if message_dict.get('msg_id') not in msg_ids:
            self.room_client.room_histories.setdefault(room_id, []).append(message_dict)
            if len(self.room_client.room_histories[room_id]) > 1000:
                self.room_client.room_histories[room_id] = self.room_client.room_histories[room_id][-1000:]
            self.save_room_history(room_id)
        self.display_room_chat(room_id)

    def on_room_file_offer(self, room_id, file_offer):
        # TODO: Show file offer popup for room file transfer
        print(f"[ROOM-DEBUG] File offer in room {room_id}: {file_offer}")

    def display_room_chat(self, room_id):
        self.chat_display.clear()
        messages = self.room_client.get_room_history(room_id)
        print(f"[ROOM-CLIENT-DEBUG] display_room_chat: {len(messages)} messages, msg_ids={[m.get('msg_id') for m in messages if isinstance(m, dict)]}")
        for msg in messages:
            sender = msg.get('sender', '')
            message = msg.get('text', '')
            self.chat_display.append(f"<b>{sender}:</b> {message}")

# Usage example (replace backend with your actual backend object):
# if __name__ == "__main__":
#     from your_backend_module import YourBackendClass
#     backend = YourBackendClass()
#     app = QApplication(sys.argv)
#     client = PyQtFederatedClient(backend)
#     client.show()
#     sys.exit(app.exec()) 