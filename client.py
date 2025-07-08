import socket
import ssl
import threading
import json
import os
import datetime
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, Listbox, ttk, scrolledtext
from cryptography.hazmat.backends import default_backend
import time
import re
import random
from client_userlist import UserListManager
from client_persistence import PersistenceManager
from client_chat import ChatManager
from client_federation import FederationManager
import encryption_utils as enc

# Gemstone list for username generation
GEMSTONES = [
    "Ruby", "Sapphire", "Emerald", "Diamond", "Amethyst", "Topaz", "Garnet", "Opal",
    "Pearl", "Jade", "Turquoise", "Aquamarine", "Citrine", "Onyx", "Quartz", "Zircon",
    "Peridot", "Tanzanite", "Alexandrite", "Moonstone", "Sunstone", "Labradorite",
    "Malachite", "Lapis", "Obsidian", "Agate", "Jasper", "Carnelian", "Chalcedony"
]

class ChatClientGUI:
    def __init__(self, server_backend, client_id):
        self.server = server_backend
        self.client_id = client_id
        # Initialize helper managers
        self.userlist = UserListManager(client_id)
        self.persistence = PersistenceManager(client_id)
        self.chat = ChatManager(client_id)
        self.federation = FederationManager(client_id)
        print('[CLIENT-REFACTOR] Modular client initialized.')
        
        # Load server configuration from config file
        import configparser
        config = configparser.ConfigParser()
        config.read('config.conf')
        self.server_host = config['Network']['host']
        self.server_port = int(config['Network']['port'])
        
        self.active_chats = {}
        self.active_rooms = {}  # Room chat history
        self.room_members = {}  # Room membership info
        self.joined_rooms = set()  # Rooms this user has joined
        self.known_rooms = {}  # Rooms we know about from other users
        self.running = True
        self.federated_servers = set()  # Set of connected federated servers
        self.current_chat_user = None  # Currently selected user to chat with
        self.current_chat_room = None  # Currently selected room to chat in
        self.chat_mode = "user"  # "user" or "room"
        self.server_status = {}  # Track online/offline status of servers
        self.user_credentials = {}  # Store username -> server mapping for verification
        
        # Load persistent data
        self.load_persistent_data()

        # Initialize GUI
        self.root = tk.Tk()
        self.root.title(f"Chat - {self.client_id}")
        self.root.geometry("600x600")
        self.root.minsize(500, 500)

        # Create menu bar
        self.create_menu_bar()

        # Create main frame
        main_frame = tk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Status bar
        status_frame = tk.Frame(main_frame)
        status_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.status_label = tk.Label(status_frame, text=f"🟢 Connected as {self.client_id}", fg="green", font=("Arial", 10))
        self.status_label.pack(side=tk.LEFT)

        # Main content area
        content_frame = tk.Frame(main_frame)
        content_frame.pack(fill=tk.BOTH, expand=True)

        # Left panel - Users and Rooms
        left_panel = tk.Frame(content_frame, width=200)
        left_panel.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        left_panel.pack_propagate(False)

        # Users section
        self.users_frame = tk.Frame(left_panel)
        self.users_frame.pack(fill=tk.BOTH, expand=True)
        
        tk.Label(self.users_frame, text="Users", font=("Arial", 12, "bold")).pack(anchor=tk.W, pady=(0, 5))
        
        # Users listbox
        self.users_listbox = tk.Listbox(self.users_frame, font=("Arial", 10))
        users_scrollbar = tk.Scrollbar(self.users_frame, orient=tk.VERTICAL, command=self.users_listbox.yview)
        self.users_listbox.config(yscrollcommand=users_scrollbar.set)
        
        self.users_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        users_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bind selection event
        self.users_listbox.bind('<<ListboxSelect>>', self.on_user_selected)
        # Bind double-click event for connection
        self.users_listbox.bind('<Double-Button-1>', self.on_user_double_clicked)
        
        # Rooms section (initially hidden)
        self.rooms_frame = tk.Frame(left_panel)
        
        tk.Label(self.rooms_frame, text="Rooms", font=("Arial", 12, "bold")).pack(anchor=tk.W, pady=(0, 5))
        
        # Rooms listbox
        self.rooms_listbox = tk.Listbox(self.rooms_frame, font=("Arial", 10))
        rooms_scrollbar = tk.Scrollbar(self.rooms_frame, orient=tk.VERTICAL, command=self.rooms_listbox.yview)
        self.rooms_listbox.config(yscrollcommand=rooms_scrollbar.set)
        
        self.rooms_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        rooms_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bind selection event
        self.rooms_listbox.bind('<<ListboxSelect>>', self.on_room_selected)

        # Right panel - Chat area
        right_panel = tk.Frame(content_frame)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # Chat header
        chat_header = tk.Frame(right_panel)
        chat_header.pack(fill=tk.X, pady=(0, 5))
        
        self.chat_title = tk.Label(chat_header, text="Select a user to start chatting", font=("Arial", 12, "bold"))
        self.chat_title.pack(side=tk.LEFT)

        # Chat messages area
        self.chat_display = scrolledtext.ScrolledText(right_panel, wrap=tk.WORD, font=("Arial", 10), state='disabled')
        self.chat_display.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        # Message input area
        input_frame = tk.Frame(right_panel)
        input_frame.pack(fill=tk.X)
        
        self.message_entry = tk.Entry(input_frame, font=("Arial", 10))
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.message_entry.bind('<Return>', self.send_message)
        
        send_button = tk.Button(input_frame, text="Send", command=self.send_message, width=8)
        send_button.pack(side=tk.RIGHT)

        # Start polling for backend messages
        threading.Thread(target=self.poll_backend_messages, daemon=True).start()
        
        # Start periodic data saving
        threading.Thread(target=self.periodic_save, daemon=True).start()
        
        # Start ping system
        threading.Thread(target=self.ping_system, daemon=True).start()

    def create_menu_bar(self):
        """Create the menu bar"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="View", menu=view_menu)
        view_menu.add_command(label="Users", command=self.show_users_tab)
        view_menu.add_command(label="Rooms", command=self.show_rooms_tab)
        view_menu.add_separator()
        view_menu.add_command(label="Refresh Users", command=self.refresh_users)
        
        # Connect menu
        connect_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Connect", menu=connect_menu)
        connect_menu.add_command(label="Connect to Server", command=self.connect_to_server)
        connect_menu.add_command(label="Test Chat", command=self.test_chat)
        
        # Room menu
        room_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Rooms", menu=room_menu)
        room_menu.add_command(label="Create Room", command=self.create_room)
        room_menu.add_command(label="Join Room", command=self.join_room)
        room_menu.add_command(label="Invite to Room", command=self.invite_to_room)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)
        help_menu.add_separator()
        help_menu.add_command(label="Settings", command=self.show_settings)
        help_menu.add_separator()
        help_menu.add_command(label="Quit", command=self.quit)

    def show_users_tab(self):
        """Switch to users tab"""
        self.chat_mode = "user"
        self.users_frame.pack(fill=tk.BOTH, expand=True)
        self.rooms_frame.pack_forget()
        # Clear current selection
        self.current_chat_user = None
        self.current_chat_room = None
        self.chat_title.config(text="Select a user to chat")
        self.chat_display.config(state='normal')
        self.chat_display.delete(1.0, tk.END)
        self.chat_display.config(state='disabled')

    def show_rooms_tab(self):
        """Switch to rooms tab"""
        self.chat_mode = "room"
        self.rooms_frame.pack(fill=tk.BOTH, expand=True)
        self.users_frame.pack_forget()
        # Clear current selection
        self.current_chat_user = None
        self.current_chat_room = None
        self.chat_title.config(text="Select a room to chat")
        self.chat_display.config(state='normal')
        self.chat_display.delete(1.0, tk.END)
        self.chat_display.config(state='disabled')
        self.update_rooms_list()

    def show_about(self):
        """Show about dialog"""
        messagebox.showinfo("About", f"Federated Chat Client\nVersion 1.0\nUser: {self.client_id}\n\nA secure peer-to-peer chat application with room support.")

    def show_settings(self):
        """Show settings dialog"""
        settings_dialog = tk.Toplevel(self.root)
        settings_dialog.title("Settings")
        settings_dialog.geometry("400x300")
        settings_dialog.transient(self.root)
        settings_dialog.grab_set()
        
        # Center the dialog
        settings_dialog.geometry("+%d+%d" % (self.root.winfo_rootx() + 50, self.root.winfo_rooty() + 50))
        
        # Username info
        tk.Label(settings_dialog, text="Username Information", font=("Arial", 12, "bold")).pack(pady=10)
        tk.Label(settings_dialog, text=f"Username: {self.client_id}", font=("Arial", 10)).pack()
        tk.Label(settings_dialog, text="(This is your unique identifier)", font=("Arial", 8), fg="gray").pack()
        
        # Display name section
        tk.Label(settings_dialog, text="Display Name", font=("Arial", 12, "bold")).pack(pady=(20, 5))
        tk.Label(settings_dialog, text="This is how others will see you:", font=("Arial", 8), fg="gray").pack()
        
        display_name_frame = tk.Frame(settings_dialog)
        display_name_frame.pack(pady=10)
        
        display_name_entry = tk.Entry(display_name_frame, font=("Arial", 10), width=20)
        display_name_entry.insert(0, self.client_id)
        display_name_entry.pack(side=tk.LEFT, padx=(0, 5))
        
        def save_display_name():
            new_name = display_name_entry.get().strip()
            if new_name:
                self.client_id = new_name
                messagebox.showinfo("Success", "Display name saved!")
                settings_dialog.destroy()
            else:
                messagebox.showerror("Error", "Display name cannot be empty")
        
        tk.Button(display_name_frame, text="Save", command=save_display_name).pack(side=tk.LEFT)
        
        # Security info
        tk.Label(settings_dialog, text="Security", font=("Arial", 12, "bold")).pack(pady=(20, 5))
        tk.Label(settings_dialog, text="• Your username is cryptographically secure", font=("Arial", 8), fg="gray").pack()
        tk.Label(settings_dialog, text="• Chat history is encrypted", font=("Arial", 8), fg="gray").pack()
        tk.Label(settings_dialog, text="• Server verification prevents impersonation", font=("Arial", 8), fg="gray").pack()

    def load_persistent_data(self):
        """Load all persistent data"""
        self.load_known_rooms()
        self.load_federated_servers()
        self.load_user_credentials()

    def save_persistent_data(self):
        """Save all persistent data"""
        self.save_known_rooms()
        self.save_federated_servers()
        self.save_user_credentials()

    def load_known_rooms(self):
        """Load known rooms from file"""
        try:
            with open(f'known_rooms_{self.client_id}.json', 'r') as f:
                self.known_rooms = json.load(f)
        except FileNotFoundError:
            self.known_rooms = {}

    def save_known_rooms(self):
        """Save known rooms to file"""
        try:
            with open(f'known_rooms_{self.client_id}.json', 'w') as f:
                json.dump(self.known_rooms, f, indent=2)
        except Exception as e:
            print(f"Error saving known rooms: {e}")

    def load_federated_servers(self):
        """Load federated servers from file"""
        try:
            with open(f'federated_servers_{self.client_id}.json', 'r') as f:
                servers = json.load(f)
                self.federated_servers = set(servers)
        except FileNotFoundError:
            self.federated_servers = set()

    def save_federated_servers(self):
        """Save federated servers to file"""
        try:
            with open(f'federated_servers_{self.client_id}.json', 'w') as f:
                json.dump(list(self.federated_servers), f, indent=2)
        except Exception as e:
            print(f"Error saving federated servers: {e}")

    def load_user_credentials(self):
        """Load user credentials from file"""
        try:
            with open(f'user_credentials_{self.client_id}.json', 'r') as f:
                self.user_credentials = json.load(f)
        except FileNotFoundError:
            self.user_credentials = {}

    def save_user_credentials(self):
        """Save user credentials to file"""
        try:
            with open(f'user_credentials_{self.client_id}.json', 'w') as f:
                json.dump(self.user_credentials, f, indent=2)
        except Exception as e:
            print(f"Error saving user credentials: {e}")

    def create_room(self):
        """Create a new room"""
        from tkinter import simpledialog
        room_name = simpledialog.askstring("Create Room", "Enter room name:")
        if room_name and room_name.strip():
            room_name = room_name.strip()
            if room_name not in self.active_rooms:
                self.active_rooms[room_name] = []
                self.room_members[room_name] = {self.client_id}
                self.joined_rooms.add(room_name)
                self.save_room_history()
                self.update_rooms_list()
                messagebox.showinfo("Room Created", f"Room '{room_name}' created successfully!")
            else:
                messagebox.showerror("Error", f"Room '{room_name}' already exists!")

    def join_room(self):
        """Join an existing room"""
        try:
            if not self.userlist.all_users:
                messagebox.showwarning("Warning", "No users available to connect to")
                return
            
            # Get available rooms from connected users
            available_rooms = self.get_available_rooms()
            
            if not available_rooms:
                messagebox.showinfo("No Rooms", "No rooms available from connected users")
                return
            
            # Create room selection dialog
            room_dialog = tk.Toplevel(self.root)
            room_dialog.title("Join Room")
            room_dialog.geometry("400x300")
            room_dialog.transient(self.root)
            room_dialog.grab_set()
            
            # Center the dialog
            room_dialog.geometry("+%d+%d" % (self.root.winfo_rootx() + 50, self.root.winfo_rooty() + 50))
            
            tk.Label(room_dialog, text="Select a room to join:", font=("Arial", 12, "bold")).pack(pady=10)
            
            # Room listbox
            room_listbox = tk.Listbox(room_dialog, font=("Arial", 10), height=10)
            room_scrollbar = tk.Scrollbar(room_dialog, orient=tk.VERTICAL, command=room_listbox.yview)
            room_listbox.config(yscrollcommand=room_scrollbar.set)
            
            room_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)
            room_scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=10)
            
            # Populate room list
            for room_info in available_rooms:
                room_name = room_info['room_name']
                owner = room_info['owner']
                member_count = room_info['member_count']
                display_text = f"📁 {room_name} (Owner: {owner}, {member_count} members)"
                room_listbox.insert(tk.END, display_text)
            
            def on_room_selected():
                selection = room_listbox.curselection()
                if selection:
                    selected_room = available_rooms[selection[0]]
                    room_name = selected_room['room_name']
                    owner = selected_room['owner']
                    
                    # Send room join request
                    self.send_server_command("room_join_request", f"{owner} {room_name}")
                    messagebox.showinfo("Join Request", f"Request sent to join room '{room_name}' via {owner}")
                    room_dialog.destroy()
            
            # Buttons
            button_frame = tk.Frame(room_dialog)
            button_frame.pack(fill=tk.X, padx=10, pady=10)
            
            tk.Button(button_frame, text="Join Selected", command=on_room_selected).pack(side=tk.LEFT, padx=(0, 5))
            tk.Button(button_frame, text="Cancel", command=room_dialog.destroy).pack(side=tk.LEFT)
            
            # Double-click to join
            room_listbox.bind('<Double-Button-1>', lambda e: on_room_selected())
            
        except Exception as e:
            print(f"Error in join_room: {e}")
            import traceback
            traceback.print_exc()
            messagebox.showerror("Error", f"Failed to join room: {e}")

    def get_available_rooms(self):
        """Get available rooms from connected users"""
        available_rooms = []
        
        # Request room lists from all connected users
        for user in self.userlist.all_users:
            if user['user_id'] != self.client_id:
                # Send room list request
                self.send_server_command("room_list_request", user['user_id'])
        
        # Return rooms we know about
        for room_name, room_info in self.known_rooms.items():
            available_rooms.append({
                'room_name': room_name,
                'owner': room_info['owner'],
                'member_count': len(room_info.get('members', []))
            })
        
        return available_rooms

    def invite_to_room(self):
        """Invite a user to a room"""
        try:
            if not self.active_rooms:
                messagebox.showwarning("Warning", "You don't have any rooms to invite people to")
                return

            if not self.userlist.all_users:
                messagebox.showwarning("Warning", "No users available to invite")
            return
            
            # Create room selection dialog
            room_dialog = tk.Toplevel(self.root)
            room_dialog.title("Invite to Room")
            room_dialog.geometry("400x300")
            room_dialog.transient(self.root)
            room_dialog.grab_set()
            
            # Center the dialog
            room_dialog.geometry("+%d+%d" % (self.root.winfo_rootx() + 50, self.root.winfo_rooty() + 50))
            
            tk.Label(room_dialog, text="Select a room to invite to:", font=("Arial", 12, "bold")).pack(pady=10)
            
            # Room listbox
            room_listbox = tk.Listbox(room_dialog, font=("Arial", 10), height=8)
            room_scrollbar = tk.Scrollbar(room_dialog, orient=tk.VERTICAL, command=room_listbox.yview)
            room_listbox.config(yscrollcommand=room_scrollbar.set)
            
            room_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)
            room_scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=10)
            
            # Populate room list
            room_names = list(self.active_rooms.keys())
            for room_name in room_names:
                member_count = len(self.room_members.get(room_name, set()))
                display_text = f"📁 {room_name} ({member_count} members)"
                room_listbox.insert(tk.END, display_text)
            
            def on_room_selected():
                selection = room_listbox.curselection()
                if selection:
                    selected_room = room_names[selection[0]]
                    room_dialog.destroy()
                    
                    # Now show user selection dialog
                    self.show_user_selection_for_invite(selected_room)
            
            # Buttons
            button_frame = tk.Frame(room_dialog)
            button_frame.pack(fill=tk.X, padx=10, pady=10)
            
            tk.Button(button_frame, text="Select Room", command=on_room_selected).pack(side=tk.LEFT, padx=(0, 5))
            tk.Button(button_frame, text="Cancel", command=room_dialog.destroy).pack(side=tk.LEFT)
            
            # Double-click to select
            room_listbox.bind('<Double-Button-1>', lambda e: on_room_selected())
            
        except Exception as e:
            print(f"Error in invite_to_room: {e}")
            import traceback
            traceback.print_exc()
            messagebox.showerror("Error", f"Failed to invite to room: {e}")

    def show_user_selection_for_invite(self, room_name):
        """Show user selection dialog for room invitation"""
        try:
            # Create user selection dialog
            user_dialog = tk.Toplevel(self.root)
            user_dialog.title(f"Invite to {room_name}")
            user_dialog.geometry("400x300")
            user_dialog.transient(self.root)
            user_dialog.grab_set()
            
            # Center the dialog
            user_dialog.geometry("+%d+%d" % (self.root.winfo_rootx() + 50, self.root.winfo_rooty() + 50))
            
            tk.Label(user_dialog, text=f"Select a user to invite to {room_name}:", font=("Arial", 12, "bold")).pack(pady=10)
            
            # User listbox
            user_listbox = tk.Listbox(user_dialog, font=("Arial", 10), height=8)
            user_scrollbar = tk.Scrollbar(user_dialog, orient=tk.VERTICAL, command=user_listbox.yview)
            user_listbox.config(yscrollcommand=user_scrollbar.set)
            
            user_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)
            user_scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=10)
            
            # Populate user list
            available_users = []
            for user in self.userlist.all_users:
                if user['user_id'] != self.client_id:
                    available_users.append(user)
                    status_icon = "🟢" if user.get('status') == 'online' else "🔴"
                    server_info = f" ({user.get('server', 'local')})" if user.get('server') != 'local' else ""
                    display_text = f"{status_icon} {user['user_id']}{server_info}"
                    user_listbox.insert(tk.END, display_text)
            
            def on_user_selected():
                selection = user_listbox.curselection()
                if selection:
                    selected_user = available_users[selection[0]]['user_id']
                    print(f"Selected user for invitation: {selected_user}")
                    user_dialog.destroy()
                    
                    # Send room invitation
                    self.send_room_invitation(selected_user, room_name)
            
            # Buttons
            button_frame = tk.Frame(user_dialog)
            button_frame.pack(fill=tk.X, padx=10, pady=10)
            
            tk.Button(button_frame, text="Invite User", command=on_user_selected).pack(side=tk.LEFT, padx=(0, 5))
            tk.Button(button_frame, text="Cancel", command=user_dialog.destroy).pack(side=tk.LEFT)
            
            # Double-click to select
            user_listbox.bind('<Double-Button-1>', lambda e: on_user_selected())
            
        except Exception as e:
            print(f"Error in show_user_selection_for_invite: {e}")
            import traceback
            traceback.print_exc()
            messagebox.showerror("Error", f"Failed to select user: {e}")

    def send_room_invitation(self, target_user, room_name):
        """Send a room invitation to a user"""
        try:
            print(f"Sending room invitation from {self.client_id} to {target_user} for room {room_name}")
            print(f"Target user: '{target_user}'")
            print(f"Room name: '{room_name}'")
            
            # Create invitation message with clickable link
            invitation_text = f"🔗 [Click to join room '{room_name}']"
            
            # Add invitation to the user's chat
            self.chat.add_chat_message(target_user, self.client_id, invitation_text)
            
            # Send the invitation through the backend
            command_args = f"{target_user} {room_name}"
            print(f"Sending command: room_invitation '{command_args}'")
            self.send_server_command("room_invitation", command_args)
            
            messagebox.showinfo("Invitation Sent", f"Room invitation sent to {target_user}")
            
        except Exception as e:
            print(f"Error in send_room_invitation: {e}")
            import traceback
            traceback.print_exc()
            messagebox.showerror("Error", f"Failed to send invitation: {e}")

    def on_room_selected(self, event):
        """Handle room selection from the list"""
        selection = self.rooms_listbox.curselection()
        if selection:
            room_name = self.rooms_listbox.get(selection[0])
            print(f"Selected room: {room_name}")
            self.current_chat_room = room_name
            self.chat_title.config(text=f"Room: {room_name}")
            self.display_room_messages(room_name)

    def display_room_messages(self, room_name):
        """Display room chat messages"""
        self.chat_display.config(state='normal')
        self.chat_display.delete(1.0, tk.END)
        
        if room_name in self.active_rooms:
            for msg in self.active_rooms[room_name]:
                self.chat_display.insert(tk.END, msg + "\n")
        
        self.chat_display.config(state='disabled')
        self.chat_display.see(tk.END)

    def add_room_message(self, room_name, sender, message):
        """Add a message to room chat history"""
        if room_name not in self.active_rooms:
            self.active_rooms[room_name] = []
        
        timestamp = datetime.datetime.now().strftime("%H:%M")
        formatted_msg = f"[{timestamp}] {sender}: {message}"
        self.active_rooms[room_name].append(formatted_msg)
        
        # If this is the currently displayed room, update the display
        if self.current_chat_room == room_name:
            self.display_room_messages(room_name)

    def update_rooms_list(self):
        """Update the rooms listbox display"""
        self.rooms_listbox.delete(0, tk.END)
        
        # Show active rooms (rooms you've joined)
        for room_name in sorted(self.active_rooms.keys()):
            member_count = len(self.room_members.get(room_name, set()))
            display_text = f"📁 {room_name} ({member_count} members)"
            self.rooms_listbox.insert(tk.END, display_text)
        
        # Show known rooms (rooms from other users)
        for room_name in sorted(self.known_rooms.keys()):
            if room_name not in self.active_rooms:  # Don't duplicate
                room_info = self.known_rooms[room_name]
                member_count = len(room_info.get('members', []))
                owner = room_info.get('owner', 'Unknown')
                display_text = f"📂 {room_name} ({member_count} members) - by {owner}"
                self.rooms_listbox.insert(tk.END, display_text)

    def save_room_history(self):
        """Save room history to file"""
        try:
            import json
            room_data = {
                'rooms': self.active_rooms,
                'members': {room: list(members) for room, members in self.room_members.items()}
            }
            with open(f'room_history_{self.client_id}.json', 'w') as f:
                json.dump(room_data, f, indent=2)
        except Exception as e:
            print(f"Error saving room history: {e}")

    def load_room_history(self):
        """Load room history from file"""
        try:
            import json
            with open(f'room_history_{self.client_id}.json', 'r') as f:
                room_data = json.load(f)
                self.active_rooms = room_data.get('rooms', {})
                self.room_members = {room: set(members) for room, members in room_data.get('members', {}).items()}
                self.joined_rooms = set(self.active_rooms.keys())
        except FileNotFoundError:
            # No saved history, start fresh
            pass

    def refresh_users(self):
        """Refresh the list of available users"""
        self.send_server_command("list_clients", "")
        # Do NOT auto-request federated user lists here!

    def update_user_status_from_server(self, server_id, is_online):
        """Update user status based on server online status"""
        try:
            # Convert server_id to different possible formats for matching
            server_formats = [server_id]
            
            # If server_id is an address like "192.168.0.98:8443", also try the client_id format
            if ':' in server_id and '.' in server_id:
                # This might be a server address, try to find the corresponding client_id
                # For now, we'll just use the address as-is
                pass
            
            # If server_id is a client_id like "user2", also try the address format
            if server_id in ['user1', 'user2']:
                # This is a client_id, try the address format
                if server_id == 'user1':
                    server_formats.append('192.168.0.10:8443')
                elif server_id == 'user2':
                    server_formats.append('192.168.0.98:8443')
            
            # Update all users from this server (try all possible formats)
            updated_users = []
            for user in self.userlist.all_users:
                if user.get('server') in server_formats:
                    old_status = user.get('status', 'unknown')
                    user['status'] = 'online' if is_online else 'offline'
                    if old_status != user['status']:
                        updated_users.append(user.get('user_id', 'unknown'))
            
            # Update known_users
            for user_id, user_info in self.userlist.known_users.items():
                if user_info.get('server') in server_formats:
                    user_info['status'] = 'online' if is_online else 'offline'
            
            # Update the display
            self.update_users_list()
            
            # Force a UI refresh to show status changes
            self.root.update_idletasks()
            
            # Only show status change when server comes online and users were actually updated
            if is_online and updated_users:
                self.chat_display.config(state='normal')
                self.chat_display.insert(tk.END, f"[{datetime.datetime.now().strftime('%H:%M')}] 🟢 Server {server_id} is now online (users: {', '.join(updated_users)})\n")
                self.chat_display.config(state='disabled')
                self.chat_display.see(tk.END)
            
        except Exception as e:
            print(f"Error updating user status: {e}")

    def on_user_selected(self, event):
        """Handle user selection from the list"""
        selection = self.users_listbox.curselection()
        print(f"User selection event: {selection}")
        if selection:
            display_index = selection[0]
            if hasattr(self, 'display_to_user') and display_index in self.display_to_user:
                user_info = self.display_to_user[display_index]
                user_id = user_info['user_id']
                print(f"Selected user: {user_id} (current_chat_user was: {self.current_chat_user})")
                if user_id != self.client_id:  # Don't chat with yourself
                    self.current_chat_user = user_id
                    self.chat_title.config(text=f"Chat with {user_id}")
                    print(f"Set current_chat_user to: {self.current_chat_user}")
                    # Create or focus chat window for this user
                    if user_id not in self.active_chats:
                        self.active_chats[user_id] = []
                    # Always display the chat messages for the selected user
                    self.display_chat_messages(user_id)
                    print(f"Displayed chat messages for user: {user_id}")
                else:
                    print(f"Cannot chat with yourself: {user_id}")
            else:
                print(f"Display index {display_index} not found in display_to_user mapping")
        else:
            print("No user selected")
            # Clear the chat display when no user is selected
            self.current_chat_user = None
            self.chat_title.config(text="Select a user to chat")
            self.chat_display.config(state='normal')
            self.chat_display.delete(1.0, tk.END)
            self.chat_display.config(state='disabled')

    def on_user_double_clicked(self, event):
        """Handle user double-click to start full connection"""
        selection = self.users_listbox.curselection()
        if selection:
            display_index = selection[0]
            if hasattr(self, 'display_to_user') and display_index in self.display_to_user:
                user_info = self.display_to_user[display_index]
                user_id = user_info['user_id']
                server = user_info.get('server', 'local')
                display_name = user_info.get('display_name', user_id)
                public_key = user_info.get('public_key', '')
                if user_id != self.client_id:
                    # Verify credentials if we have stored data
                    if user_id in self.user_credentials:
                        verified, message = self.verify_user_credentials(
                            user_id, 
                            server, 
                            public_key
                        )
                        if not verified:
                            result = messagebox.askyesno(
                                "Security Warning", 
                                f"Credential mismatch detected!\n\n{message}\n\nDo you want to proceed anyway?"
                            )
                            if not result:
                                return
                    # Check if we need to connect to the user's server first
                    if server and server != 'local' and server != self.client_id and server not in self.federated_servers:
                        address = self.convert_server_to_address(server)
                        print(f"Double-click: Connecting to {user_id}'s server at {address}")
                        if ':' in address and address != server:
                            self.send_server_command("connection_request", address)
                            self.chat_display.config(state='normal')
                            self.chat_display.insert(tk.END, f"[{datetime.datetime.now().strftime('%H:%M')}] 🔗 Connecting to {display_name}'s server at {address}...\n")
                            self.chat_display.config(state='disabled')
                            self.chat_display.see(tk.END)
                            # After connection, explicitly request federated user list
                            self.send_server_command("fetch_federated_users", server)
                        else:
                            messagebox.showerror("Connection Error", f"Cannot connect to {display_name}: Invalid server address '{server}'")
                    else:
                        self.send_server_command("direct_chat_request", f"{user_id} {display_name}")
                        print(f"Sent direct chat request to {display_name} ({user_id})")
                        self.chat_display.config(state='normal')
                        self.chat_display.insert(tk.END, f"[{datetime.datetime.now().strftime('%H:%M')}] 🔗 Requesting connection to {display_name}...\n")
                        self.chat_display.config(state='disabled')
                        self.chat_display.see(tk.END)

    def display_chat_messages(self, user_id):
        """Display chat messages for the selected user"""
        self.chat_display.config(state='normal')
        self.chat_display.delete(1.0, tk.END)
        
        if user_id in self.active_chats:
            for msg in self.active_chats[user_id]:
                self.chat_display.insert(tk.END, msg + "\n")
        
        self.chat_display.config(state='disabled')
        self.chat_display.see(tk.END)

    def add_chat_message(self, user_id, sender, message):
        """Add a message to the chat history"""
        if user_id not in self.active_chats:
            self.active_chats[user_id] = []
        
        timestamp = datetime.datetime.now().strftime("%H:%M")
        formatted_msg = f"[{timestamp}] {sender}: {message}"
        self.active_chats[user_id].append(formatted_msg)
        
        # If this is the currently displayed chat, update the display
        if self.current_chat_user == user_id:
            self.display_chat_messages(user_id)

    def send_message(self, event=None):
        """Send a message to the currently selected user or room"""
        message = self.message_entry.get().strip()
        if not message:
            return
        
        if self.chat_mode == "user":
            if not self.current_chat_user:
                messagebox.showwarning("Warning", "Please select a user to chat with")
                return
            
            # Add message to local chat history
            self.add_chat_message(self.current_chat_user, self.client_id, message)
            
            # Send message to the user
            self.send_server_command("chat_message", f"{self.current_chat_user} {message}")
        
        elif self.chat_mode == "room":
            if not self.current_chat_room:
                messagebox.showwarning("Warning", "Please select a room to chat in")
            return
            
            # Add message to local room history
            self.add_room_message(self.current_chat_room, self.client_id, message)
            
            # Send message to the room
            self.send_server_command("room_message", f"{self.current_chat_room} {message}")
        
        # Clear input field
        self.message_entry.delete(0, tk.END)

    def update_users_list(self):
        """Update the users listbox display using UserListManager"""
        try:
            display_users = self.userlist.get_display_users()
            print(f"[GUI-DEBUG-REBUILD] update_users_list called. display_users: {display_users}")
            self.users_listbox.delete(0, tk.END)
            self.userlist.update_display_mapping()
            for display_index, user in self.userlist.display_to_user.items():
                user_id = user.get('user_id', '')
                display_name = user.get('display_name', user_id)
                server = user.get('server', 'local')
                status = user.get('status', 'unknown')
                public_key = user.get('public_key', '')
                print(f"[GUI-DEBUG-REBUILD] Displaying user: {user}")
                security_warning = ""
                if user_id in self.userlist.user_credentials:
                    verified, message = self.verify_user_credentials(user_id, server, public_key)
                    if not verified:
                        security_warning = " ⚠️"
                if status == 'online':
                    status_icon = "🟢"
                elif status == 'offline':
                    status_icon = "🔴"
                else:
                    status_icon = "⚪"
                server_info = f" ({server})" if server != 'local' else ""
                display_text = f"{status_icon} {display_name}{security_warning}{server_info}"
                self.users_listbox.insert(tk.END, display_text)
            print(f"[GUI-DEBUG-REBUILD] update_users_list display_to_user: {self.userlist.display_to_user}")
        except Exception as e:
            print(f"Error in update_users_list: {e}")
            import traceback
            traceback.print_exc()

    def force_refresh_users(self):
        """Force a full refresh of the user list from known sources using UserListManager"""
        print("[GUI-DEBUG-REBUILD] force_refresh_users called")
        self.userlist.clear()
        self.userlist.load_known_users(self.persistence.load_known_users())
        self.update_users_list()

    def poll_backend_messages(self):
        """Poll for messages from the backend"""
        while self.running:
            try:
                msg = self.server.get_message_for_client(timeout=0.1)
                if msg is None:
                    continue
                msg_type = msg.get('type')
                print(f"Client received message: {msg_type} - {msg}")
                
                if msg_type == 'chat_message':
                    from_user = msg.get('from_client', msg.get('from', 'Unknown'))
                    message = msg.get('message', '')
                    print(f"Client processing chat message from {from_user}: {message}")
                    self.add_chat_message(from_user, from_user, message)
                    # If this message is from the currently selected user, update the display
                    if self.current_chat_user == from_user:
                        print(f"Updating display for current chat user: {from_user}")
                        self.display_chat_messages(from_user)
                
                elif msg_type == 'direct_chat_message':
                    from_user = msg.get('from_client', 'Unknown')
                    message = msg.get('message', '')
                    self.add_chat_message(from_user, from_user, message)
                    # If this message is from the currently selected user, update the display
                    if self.current_chat_user == from_user:
                        print(f"Updating display for current chat user: {from_user}")
                        self.display_chat_messages(from_user)
                
                elif msg_type == 'direct_chat_request':
                    from_user = msg.get('from_client', 'Unknown')
                    from_server = msg.get('from_server', 'Unknown')
                    message = msg.get('message', f'Chat request from {from_user}')
                    
                    # Show approval dialog
                    result = messagebox.askyesno("Chat Request", 
                                               f"{message}\n\nUser: {from_user}\nServer: {from_server}\n\nAccept this chat request?")
                    
                    if result:
                        # Accept the chat request
                        self.send_server_command("direct_chat_response", f"{from_user} accept")
                        # Add the user to our chat list if not already there
                        self.userlist.add_or_update_user(from_user, from_server)
                    else:
                        # Reject the chat request
                        self.send_server_command("direct_chat_response", f"{from_user} reject")
                
                elif msg_type == 'direct_chat_response':
                    from_user = msg.get('from_client', 'Unknown')
                    response = msg.get('response', 'reject')
                    
                    if response == 'accept':
                        # Show success message
                        self.chat_display.config(state='normal')
                        self.chat_display.insert(tk.END, f"[{datetime.datetime.now().strftime('%H:%M')}] ✅ Chat request accepted by {from_user}\n")
                        self.chat_display.config(state='disabled')
                        self.chat_display.see(tk.END)
                    else:
                        # Show rejection message
                        self.chat_display.config(state='normal')
                        self.chat_display.insert(tk.END, f"[{datetime.datetime.now().strftime('%H:%M')}] ❌ Chat request rejected by {from_user}\n")
                        self.chat_display.config(state='disabled')
                        self.chat_display.see(tk.END)
                
                elif msg_type == 'room_message':
                    room_name = msg.get('room_name', '')
                    from_user = msg.get('from_client', 'Unknown')
                    message = msg.get('message', '')
                    print(f"Client processing room message from {from_user} in {room_name}: {message}")
                    # Clean room name if it contains display text
                    if room_name.startswith('📁 '):
                        room_name = room_name[2:]  # Remove the folder icon
                    if ' (' in room_name:
                        room_name = room_name.split(' (')[0]  # Remove member count
                    self.add_room_message(room_name, from_user, message)
                    # If this message is for the currently selected room, update the display
                    if self.current_chat_room == room_name:
                        print(f"Updating display for current room: {room_name}")
                        self.display_room_messages(room_name)
                
                elif msg_type == 'room_join_response':
                    room_name = msg.get('room_name', '')
                    accepted = msg.get('accepted', False)
                    from_user = msg.get('from_client', '')
                    if accepted:
                        self.active_rooms[room_name] = []
                        self.room_members[room_name] = {self.client_id, from_user}
                        self.joined_rooms.add(room_name)
                        self.save_room_history()
                        self.update_rooms_list()
                        messagebox.showinfo("Room Joined", f"Successfully joined room '{room_name}'!")
                    else:
                        messagebox.showwarning("Join Rejected", f"Request to join room '{room_name}' was rejected")
                
                elif msg_type == 'room_invite':
                    room_name = msg.get('room_name', '')
                    from_user = msg.get('from_client', '')
                    result = messagebox.askyesno("Room Invite", f"User {from_user} invites you to join room '{room_name}'. Accept?")
                    if result:
                        # Accept the invite
                        self.send_server_command("room_join_accept", f"{from_user} {room_name}")
                        self.active_rooms[room_name] = []
                        self.room_members[room_name] = {self.client_id, from_user}
                        self.joined_rooms.add(room_name)
                        self.save_room_history()
                        self.update_rooms_list()
                    else:
                        # Reject the invite
                        self.send_server_command("room_join_reject", f"{from_user} {room_name}")
                
                elif msg_type == 'room_invitation':
                    room_name = msg.get('room_name', '')
                    from_user = msg.get('from_client', '')
                    # Add invitation message to chat with clickable link
                    invitation_text = f"🔗 [Click to join room '{room_name}']"
                    self.add_chat_message(from_user, from_user, invitation_text)
                    # If this is the currently displayed chat, update the display
                    if self.current_chat_user == from_user:
                        self.display_chat_messages(from_user)
                elif msg_type == 'ping_response':
                    server_id = msg.get('server_id', '')
                    is_online = msg.get('online', False)
                    was_online = self.server_status.get(server_id, False)
                    self.server_status[server_id] = is_online
                    
                    # Only print status changes
                    if is_online != was_online:
                        if is_online:
                            print(f"Server {server_id} is now online")
                        else:
                            print(f"Server {server_id} is now offline")
                    
                    # Update user status based on server status
                    self.update_user_status_from_server(server_id, is_online)
                
                elif msg_type == 'online_check_response':
                    from_client = msg.get('from_client')
                    to_client = msg.get('to_client')
                    is_online = msg.get('online', False)
                    print(f"Client received online check response: {from_client} is {'online' if is_online else 'offline'}")
                    
                    # Update user status in the user list
                    user_found = False
                    for user in self.userlist.all_users:
                        if user.get('user_id') == from_client:
                            user['status'] = 'online' if is_online else 'offline'
                            user_found = True
                            break
                    
                    # If user not in all_users, add them
                    if not user_found and is_online:
                        # Try to find user info from known_users
                        if from_client in self.userlist.known_users:
                            user_info = self.userlist.known_users[from_client]
                            new_user = {
                                'user_id': from_client,
                                'server': user_info.get('server', 'unknown'),
                                'status': 'online',
                                'display_name': from_client
                            }
                            self.userlist.add_or_update_user(from_client, new_user.get('server', 'unknown'))
                    
                    # Update known users
                    if from_client in self.userlist.known_users:
                        self.userlist.known_users[from_client]['status'] = 'online' if is_online else 'offline'
                        self.userlist.known_users[from_client]['last_seen'] = datetime.datetime.now().isoformat()
                    
                    # Update the UI
                    self.update_users_list()
                    self.save_persistent_data()
                    
                    # Force a UI refresh to show status changes
                    self.root.update_idletasks()
                elif msg_type == 'user_directory':
                    directory = msg.get('directory', {})
                    print(f"Received USER_DIRECTORY: {directory}")
                    # Send online checks to users from USER_DIRECTORY (but not too frequently)
                    current_time = time.time()
                    if not hasattr(self, 'last_online_check') or current_time - self.last_online_check > 30:
                        self.last_online_check = current_time
                        for user_id, server in directory.items():
                            if user_id != self.client_id:  # Don't check ourselves
                                self.send_server_command("online_check", user_id)
                elif msg_type == 'room_list_response':
                    # Handle room list response from other users
                    from_user = msg.get('from_client', '')
                    rooms = msg.get('rooms', [])
                    print(f"Received room list from {from_user}: {rooms}")
                    
                    # Update known rooms
                    for room_info in rooms:
                        room_name = room_info['room_name']
                        # Clean room name if it contains display text
                        if room_name.startswith('📁 '):
                            room_name = room_name[2:]  # Remove the folder icon
                        if ' (' in room_name:
                            room_name = room_name.split(' (')[0]  # Remove member count
                        
                        self.userlist.known_rooms[room_name] = {
                            'owner': from_user,
                            'members': room_info.get('members', []),
                            'last_updated': datetime.datetime.now().isoformat()
                        }
                    
                    self.save_persistent_data()
                elif msg_type == 'get_my_rooms':
                    # Send our room list to the backend for federated requests
                    rooms = []
                    for room_name, room_messages in self.active_rooms.items():
                        members = list(self.room_members.get(room_name, set()))
                        rooms.append({
                            'room_name': room_name,
                            'members': members
                        })
                    
                    # Send room list to backend
                    self.send_server_command("room_list_response", f"{self.client_id} {json.dumps(rooms)}")
                
                elif msg_type == 'client_list':
                    local_users = msg.get('all_users', [])
                    federated_users = [u for u in self.userlist.all_users if u.get('server') != 'local' and u.get('server') != self.client_id]
                    # Add/update all users
                    for user in local_users + federated_users:
                        self.userlist.add_or_update_user(user)
                    self.userlist.deduplicate()
                    self.update_users_list()
                elif msg_type == 'federated_users':
                    federated_users = msg.get('users', [])
                    print(f"Client received federated users: {federated_users}")
                    from_server = msg.get('from_server')
                    # Remove users from the same server
                    self.userlist.all_users = [u for u in self.userlist.all_users if u.get('server') != from_server]
                    for user in federated_users:
                        self.userlist.add_or_update_user(user)
                    self.userlist.deduplicate()
                    for user in federated_users:
                        user_id = user.get('user_id', '')
                        if user_id:
                            self.userlist.known_users[user_id] = {
                                'server': user.get('server', 'unknown'),
                                'status': user.get('status', 'unknown'),
                                'last_seen': datetime.datetime.now().isoformat()
                            }
                    self.save_persistent_data()
                    self.update_users_list()
                    print(f"[GUI-DEBUG-REBUILD] poll_backend_messages federated_users updated all_users: {self.userlist.all_users}")
                elif msg_type == 'user_list_response':
                    federated_users = msg.get('users', [])
                    from_server = msg.get('from_server')
                    server_address = msg.get('server_address', from_server)
                    print(f"Client received user_list_response from {from_server} (address: {server_address}): {federated_users}")
                    self.userlist.all_users = [u for u in self.userlist.all_users if u.get('server') != from_server]
                    for user in federated_users:
                        user['server'] = server_address
                        self.userlist.add_or_update_user(user)
                        user_id = user.get('user_id', '')
                        if user_id and user_id not in self.userlist.known_users:
                            print(f"[GUI-DEBUG-REBUILD] Adding new user to known_users: {user_id}")
                            self.userlist.known_users[user_id] = {
                                'server': server_address,
                                'status': user.get('status', 'unknown'),
                                'last_seen': datetime.datetime.now().isoformat()
                            }
                    self.userlist.deduplicate()
                    for user in federated_users:
                        user_id = user.get('user_id', '')
                        if user_id:
                            self.userlist.known_users[user_id] = {
                                'server': server_address,
                                'status': user.get('status', 'unknown'),
                                'last_seen': datetime.datetime.now().isoformat()
                            }
                    self.save_persistent_data()
                    self.update_users_list()
                    print(f"[GUI-DEBUG-REBUILD] poll_backend_messages user_list_response updated all_users: {self.userlist.all_users}")
                elif msg_type == 'server_connected':
                    server_id = msg.get('server_id')
                    if server_id and server_id not in self.federated_servers:
                        self.federated_servers.add(server_id)
                        # Show connection success in chat area
                        self.chat_display.config(state='normal')
                        self.chat_display.insert(tk.END, f"[{datetime.datetime.now().strftime('%H:%M')}] ✅ Connected to federated server: {server_id}\n")
                        self.chat_display.config(state='disabled')
                        self.chat_display.see(tk.END)
                        # Force refresh user list to get federated users
                        print(f"[GUI-DEBUG-REBUILD] Auto-fetching federated users from {server_id}")
                        self.send_server_command("fetch_federated_users", server_id)
                        self.update_rooms_list()
                        # Immediately refresh users list in GUI
                        self.refresh_users()
                
                elif msg_type == 'error':
                    messagebox.showerror("Error", msg.get('message', 'Unknown error'))
                
                elif msg_type == 'info':
                    # Suppress the popup for 'Sent user list to 0 federated servers'
                    info_msg = msg.get('message', '')
                    if info_msg.strip().startswith('Sent user list to 0 federated servers'):
                        print(f"[INFO] {info_msg}")
                    else:
                        messagebox.showinfo("Info", info_msg)
                
                elif msg_type == 'federated_connection_request':
                    # Handle federated connection request from another server
                    server_id = msg.get('server_id')
                    server_address = msg.get('server_address')
                    message_text = msg.get('message')
                    self.handle_federated_connection_request(server_id, server_address, message_text)
                
                else:
                    print(f"Unknown message type: {msg_type}, message: {msg}")
                
            except Exception as e:
                print(f"Error in poll_backend_messages: {e}")
                import traceback
                traceback.print_exc()
                
            time.sleep(0.05)

    def periodic_save(self):
        """Periodically save persistent data"""
        while self.running:
            try:
                time.sleep(30)  # Save every 30 seconds
                if self.running:
                    self.save_persistent_data()
                    self.save_room_history()
            except Exception as e:
                print(f"Error in periodic save: {e}")

    def quit(self):
        """Clean shutdown"""
        self.running = False
        self.save_persistent_data()
        self.save_room_history()
        self.root.quit()
    
    def handle_server_key_mismatch(self, server_id, old_key, new_key, address):
        """Handle server key mismatch warning"""
        result = messagebox.askyesno(
            "Server Key Mismatch",
            f"Server {server_id} ({address}) has a different public key than previously stored.\n\n"
            f"This could indicate:\n"
            f"• The server was reinstalled\n"
            f"• A different server is using the same address\n"
            f"• A security issue\n\n"
            f"Do you want to approve the new key and continue?",
            icon='warning'
        )
        
        if result:
            # Send approval command to backend
            self.send_server_command("approve_server_key", f"{server_id} {new_key}")
        else:
            print(f"User rejected new key for server {server_id}")
    
    def handle_federated_connection_request(self, server_id, server_address, message_text):
        """Handle federated connection request from another server"""
        result = messagebox.askyesno(
            "Federated Connection Request",
            f"{message_text}\n\n"
            f"Server ID: {server_id}\n"
            f"Address: {server_address}\n\n"
            f"Do you want to allow this connection?",
            icon='question'
        )
        
        if result:
            # Send approval command to backend
            self.send_server_command("approve_federated_connection", server_id)
            print(f"User approved connection from federated server {server_id}")
        else:
            # Send rejection command to backend
            self.send_server_command("reject_federated_connection", server_id)
            print(f"User rejected connection from federated server {server_id}")

    def ping_system(self):
        """Periodically ping known servers to check online status"""
        while self.running:
            try:
                # Remove all logic that uses convert_server_to_address
                # If you want to ping servers, just iterate over known server addresses directly
                time.sleep(10)
            except Exception as e:
                print(f"Error in ping system: {e}")

    def test_chat(self):
        """Send a test message to the first available user"""
        try:
            if not self.userlist.all_users:
                messagebox.showwarning("Warning", "No users available")
            return
            
            # Find first user that's not yourself
            for user in self.userlist.all_users:
                if user['user_id'] != self.client_id:
                    test_user = user['user_id']
                    test_message = f"Hello from {self.client_id}! This is a test message."
                    print(f"Sending test message to {test_user}: {test_message}")
                    self.send_server_command("chat_message", f"{test_user} {test_message}")
                    messagebox.showinfo("Test Chat", f"Sent test message to {test_user}")
            return
            
            messagebox.showwarning("Warning", "No other users available")
        except Exception as e:
            print(f"Error in test_chat: {e}")
            import traceback
            traceback.print_exc()
            messagebox.showerror("Error", f"Test chat failed: {e}")

    def connect_to_server(self):
        """Connect to a federated server with proper request/approval flow"""
        try:
            from tkinter import simpledialog
            address = simpledialog.askstring("Connect to Server", 
                                           "Enter server address:\nExamples:\n- 192.168.1.100:8443\n- myserver.com:8443\n- localhost:8443")
            if address:
                # Validate the address format
                if ':' in address:
                    try:
                        host, port_str = address.rsplit(':', 1)
                        port = int(port_str)
                        if port <= 0 or port > 65535:
                            messagebox.showerror("Error", "Port must be between 1 and 65535")
                            return
                    except ValueError:
                        messagebox.showerror("Error", "Invalid port number")
                        return
                else:
                    # Add default port if not specified
                    address = f"{address}:8443"
                
                # Send connection request
                self.send_server_command("connection_request", address)
                
                # Show status message in chat area
                try:
                    self.chat_title.config(text="Requesting connection...")
                    self.chat_display.config(state='normal')
                    self.chat_display.insert(tk.END, f"[{datetime.datetime.now().strftime('%H:%M')}] Sending connection request to {address}...\n")
                    self.chat_display.config(state='disabled')
                    self.chat_display.see(tk.END)
                except Exception as e:
                    print(f"Error updating chat display: {e}")
                    # Fallback: show message box instead
                    messagebox.showinfo("Connection", f"Sending connection request to {address}...")
                    
        except Exception as e:
            print(f"Error in connect_to_server: {e}")
            import traceback
            traceback.print_exc()
            messagebox.showerror("Error", f"Connection failed: {e}")

    def send_server_command(self, command, args):
        """Send a command to the backend"""
        if not self.running:
            messagebox.showerror("Error", "Client is not running")
            return
        if hasattr(self.server, 'handle_client_command'):
            self.server.handle_client_command(command, args)
        else:
            messagebox.showerror("Error", "Backend does not support command handling")

    def quit(self):
        """Quit the application"""
        # Save persistent data before quitting
        self.save_persistent_data()
        self.save_room_history()
        self.running = False
        self.root.quit()

def run_client(server_host, server_port, client_id):
    app = ChatClientGUI(server_host, server_port, client_id)
    app.root.mainloop()