import sys
import os
import json
import threading
from PyQt6.QtWidgets import (
    QApplication, QWidget, QListWidget, QTextEdit, QLineEdit, QPushButton, QVBoxLayout, QHBoxLayout, QListWidgetItem, QMessageBox, QInputDialog, QMenu
)
from PyQt6.QtCore import Qt, QTimer

class PyQtFederatedClient(QWidget):
    def __init__(self, backend, client_id=None):
        super().__init__()
        self.backend = backend
        self.client_id = client_id or "Unknown"
        self.setWindowTitle(f"Federated Chat Client (PyQt6) - {self.client_id}")
        self.resize(700, 500)
        self.contacts = {}  # address -> username
        self.active_chats = {}  # address -> [(sender, message)]
        self.current_server = None
        self.contacts_file = "server_contacts.json"
        self.automated_message_sent = set()  # Track which contacts have received the auto message
        self.pending_contact_key_approval = set()  # addresses for which a contact request is pending key approval
        self.load_contacts()
        self.init_ui()
        self.poll_timer = QTimer()
        self.poll_timer.timeout.connect(self.poll_backend)
        self.poll_timer.start(100)

    def init_ui(self):
        main_layout = QHBoxLayout(self)
        # Left panel (vertical layout)
        left_panel = QVBoxLayout()
        self.username_label = QPushButton(f"Username: {self.client_id}")
        self.username_label.setEnabled(False)
        left_panel.addWidget(self.username_label)
        self.connect_button = QPushButton("Add Contact")
        self.connect_button.clicked.connect(self.on_add_contact)
        left_panel.addWidget(self.connect_button)
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
        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True)
        chat_layout.addWidget(self.chat_display, 8)
        # Message entry
        entry_layout = QHBoxLayout()
        self.message_entry = QLineEdit()
        self.message_entry.returnPressed.connect(self.on_send_message)
        entry_layout.addWidget(self.message_entry, 8)
        self.send_button = QPushButton("Send")
        self.send_button.clicked.connect(self.on_send_message)
        entry_layout.addWidget(self.send_button, 2)
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
            except Exception:
                self.contacts = {}
        else:
            self.contacts = {}

    def save_contacts(self):
        try:
            with open(self.contacts_file, 'w') as f:
                json.dump({'contacts': self.contacts}, f)
        except Exception:
            pass

    def update_contact(self, address, username):
        if not address or not username:
            return
        self.contacts[address] = username
        self.save_contacts()
        self.update_contact_list()

    def update_contact_list(self):
        self.contact_list.clear()
        for address, username in sorted(self.contacts.items(), key=lambda x: x[1]):
            item = QListWidgetItem(f"{username} ({address})")
            self.contact_list.addItem(item)

    def refresh_contacts_from_backend(self):
        try:
            contacts = self.backend.get_contacts()
            # If backend returns only addresses, keep old usernames if possible
            for addr in contacts:
                if addr not in self.contacts:
                    self.contacts[addr] = addr
            self.update_contact_list()
        except Exception as e:
            print(f"[CLIENT-DEBUG] refresh_contacts_from_backend error: {e}")

    def poll_backend(self):
        try:
            msg = self.backend.get_message(timeout=0.01)
            if not msg:
                return
            print(f"[CLIENT-DEBUG] poll_backend received: {msg}")
            msg_type = msg.get('type')
            if msg_type == 'chat_message':
                address = msg.get('from_server') or msg.get('address')
                from_client = msg.get('from_client', address)
                message = msg.get('message')
                if address not in self.active_chats:
                    self.active_chats[address] = []
                self.active_chats[address].append((from_client, message))
                self.display_chat(address)
                if self.current_server != address:
                    self.current_server = address
                    self.display_chat(address)
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
                # Only send automated message if this is a new contact and we haven't sent it before
                if is_new and username != self.client_id and address not in self.automated_message_sent:
                    auto_msg = f"{self.client_id} has accepted your chat request."
                    print(f"[CLIENT-DEBUG] Sending automated acceptance message to {address}: {auto_msg}")
                    self.backend.send_command('chat_message', f'{address} {auto_msg}')
                    self.automated_message_sent.add(address)
            elif msg_type == 'info':
                print(f"[CLIENT-DEBUG] info event: {msg.get('message')}")
                self.refresh_contacts_from_backend()
                QMessageBox.information(self, "Info", msg.get('message', ''))
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

    def on_select_contact(self, current, previous):
        if current is None:
            return
        idx = self.contact_list.currentRow()
        address = list(sorted(self.contacts.keys(), key=lambda x: self.contacts[x]))[idx]
        self.current_server = address
        self.display_chat(address)

    def display_chat(self, address):
        self.chat_display.clear()
        messages = self.active_chats.get(address, [])
        for sender, message in messages:
            # Map sender to username if possible
            if sender == self.client_id:
                display_name = "You"
            elif sender in self.contacts.values():
                # sender is a username
                display_name = sender
            elif sender in self.contacts:
                # sender is an address
                display_name = self.contacts.get(sender, sender)
            else:
                display_name = sender
            self.chat_display.append(f"<b>{display_name}:</b> {message}")

    def on_send_message(self):
        message = self.message_entry.text().strip()
        print(f"[CLIENT-DEBUG] on_send_message called: message='{message}', current_server='{self.current_server}'")
        if not message or not self.current_server:
            print("[CLIENT-DEBUG] on_send_message: No message or no contact selected.")
            return
        address = self.current_server
        if address not in self.active_chats:
            self.active_chats[address] = []
        self.active_chats[address].append((self.client_id, message))
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
        address = list(sorted(self.contacts.keys(), key=lambda x: self.contacts[x]))[idx]
        menu = QMenu()
        remove_action = menu.addAction(f"Remove {address}")
        action = menu.exec(self.contact_list.mapToGlobal(pos))
        if action == remove_action:
            del self.contacts[address]
            self.save_contacts()
            self.update_contact_list()
            if self.current_server == address:
                self.current_server = None
                self.chat_display.clear()

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

# Usage example (replace backend with your actual backend object):
# if __name__ == "__main__":
#     from your_backend_module import YourBackendClass
#     backend = YourBackendClass()
#     app = QApplication(sys.argv)
#     client = PyQtFederatedClient(backend)
#     client.show()
#     sys.exit(app.exec()) 