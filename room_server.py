import json
import os
from room_protocol import (
    Room, generate_room_id, hash_password, check_password,
    ROOM_CREATE, ROOM_INVITE, ROOM_JOIN, ROOM_LEAVE, ROOM_MESSAGE,
    ROOM_HISTORY_REQUEST, ROOM_HISTORY_RESPONSE, ROOM_FILE_OFFER
)
from typing import Dict, Optional, List
import threading

ROOMS_DATA_FILE = 'rooms_data.json'

class RoomManager:
    """Manages all rooms and their state."""
    def __init__(self):
        self.rooms: Dict[str, Room] = {}  # room_id -> Room
        self.lock = threading.RLock()
        self.load_rooms()

    def save_rooms(self):
        with self.lock:
            try:
                data = {rid: room.to_dict() for rid, room in self.rooms.items()}
                with open(ROOMS_DATA_FILE, 'w') as f:
                    json.dump(data, f)
            except Exception as e:
                print(f"[ROOM-SERVER] Failed to save rooms: {e}")

    def load_rooms(self):
        if os.path.exists(ROOMS_DATA_FILE):
            try:
                with open(ROOMS_DATA_FILE, 'r') as f:
                    data = json.load(f)
                    for rid, room_dict in data.items():
                        self.rooms[rid] = Room.from_dict(room_dict)
            except Exception as e:
                print(f"[ROOM-SERVER] Failed to load rooms: {e}")

    def create_room(self, name: str, creator_id: str, is_private: bool, password: Optional[str] = None, server_addr: Optional[str] = None) -> Room:
        with self.lock:
            # Ensure unique room name
            for room in self.rooms.values():
                if room.name == name:
                    raise ValueError('Room name already exists')
            room_id = generate_room_id()
            password_hash = hash_password(password) if is_private and password else None
            room = Room(room_id, name, is_private, password_hash)
            room.add_member(creator_id)
            # --- Federated: initialize userlist with creator's server address ---
            room.userlist = set()
            if server_addr:
                room.userlist.add(server_addr)
            self.rooms[room_id] = room
            self.save_rooms()
            return room

    def find_full_room_id(self, short_id: str) -> Optional[str]:
        """Find the full room ID given a short (6-char) ID. Returns None if not found or ambiguous."""
        matches = [rid for rid in self.rooms if rid.startswith(short_id)]
        if len(matches) == 1:
            return matches[0]
        return None

    def get_room(self, room_id: str) -> Optional[Room]:
        # Accept both full and short room IDs
        room = self.rooms.get(room_id)
        if room:
            return room
        # Try short ID lookup
        full_id = self.find_full_room_id(room_id)
        if full_id:
            return self.rooms[full_id]
        return None

    def get_userlist(self, room_id: str) -> set:
        room = self.get_room(room_id)
        if room:
            return set(room.userlist)
        return set()

    def set_userlist(self, room_id: str, userlist: set):
        room = self.get_room(room_id)
        if room:
            room.userlist = set(userlist)
            self.save_rooms()

    def merge_userlist(self, room_id: str, userlist: set):
        room = self.get_room(room_id)
        if room:
            if not hasattr(room, 'userlist'):
                room.userlist = set()
            room.userlist.update(userlist)
            self.save_rooms()

    def join_room(self, room_id: str, user_id: str, password: Optional[str] = None, server_addr: Optional[str] = None) -> bool:
        with self.lock:
            room = self.get_room(room_id)
            if not room:
                return False
            if room.is_private and not room.check_password(password):
                return False
            # Add server_addr to userlist, not user_id
            if server_addr:
                room.userlist.add(server_addr)
            else:
                # Fallback: add user_id only if it's a valid server address
                if ':' in user_id:
                    room.userlist.add(user_id)
            room.add_member(user_id)
            self.save_rooms()
            return True

    def leave_room(self, room_id: str, user_id: str, server_addr: Optional[str] = None) -> bool:
        with self.lock:
            room = self.get_room(room_id)
            if not room:
                return False
            # Remove server_addr from userlist, not user_id
            if server_addr and server_addr in room.userlist:
                room.userlist.remove(server_addr)
            elif ':' in user_id and user_id in room.userlist:
                room.userlist.remove(user_id)
            room.remove_member(user_id)
            self.save_rooms()
            return True

    def add_message(self, room_id: str, message: dict):
        with self.lock:
            room = self.rooms.get(room_id)
            if room:
                room.add_message(message)
                self.save_rooms()

    def get_history(self, room_id: str) -> Optional[List[dict]]:
        room = self.rooms.get(room_id)
        if room:
            return room.history
        return None

    def get_members(self, room_id: str) -> Optional[List[str]]:
        room = self.rooms.get(room_id)
        if room:
            return list(room.members)
        return None

def broadcast_userlist_update(manager, room_id, federation, local_server_addr):
    userlist = manager.get_userlist(room_id)
    if not userlist or not federation or not local_server_addr:
        return
    for server_addr in userlist:
        if server_addr != local_server_addr:
            try:
                host, port = server_addr.split(':')
                port = int(port)
                federation.send_message(server_addr, port, {
                    'type': 'federated_room_userlist_update',
                    'room_id': room_id,
                    'userlist': list(userlist)
                }, plaintext=True)
            except Exception as e:
                print(f"[ROOM-SERVER-DEBUG] Failed to federate userlist update to {server_addr}: {e}")


def handle_room_message(manager: RoomManager, msg: dict, sender_id: str, send_func, federation=None, local_server_addr=None):
    """
    Handles incoming room-related messages.
    send_func(target_id, message_dict) should send a message to a user.
    federation: Federation object for cross-server messaging (optional)
    local_server_addr: This server's address (host:port) (optional)
    """
    msg_type = msg.get('type')
    if msg_type == ROOM_CREATE:
        # {type, name, is_private, password (optional)}
        try:
            room = manager.create_room(
                name=msg['name'],
                creator_id=sender_id,
                is_private=msg.get('is_private', False),
                password=msg.get('password'),
                server_addr=local_server_addr
            )
            # Notify creator of success
            send_func(sender_id, {'type': 'room_create_success', 'room': room.to_dict()})
            # Broadcast userlist update
            broadcast_userlist_update(manager, room.room_id, federation, local_server_addr)
        except ValueError as e:
            send_func(sender_id, {'type': 'room_create_error', 'error': str(e)})
    elif msg_type == ROOM_JOIN:
        # {type, room_id, password (optional)}
        success = manager.join_room(msg['room_id'], sender_id, msg.get('password'), server_addr=local_server_addr)
        if success:
            room = manager.get_room(msg['room_id'])
            send_func(sender_id, {'type': 'room_join_success', 'room': room.to_dict()})
            # Broadcast userlist update
            broadcast_userlist_update(manager, room.room_id, federation, local_server_addr)
            # Optionally notify other members
        else:
            send_func(sender_id, {'type': 'room_join_error', 'error': 'Join failed'})
    elif msg_type == ROOM_LEAVE:
        # {type, room_id}
        manager.leave_room(msg['room_id'], sender_id, server_addr=local_server_addr)
        send_func(sender_id, {'type': 'room_leave_success', 'room_id': msg['room_id']})
        # Broadcast userlist update
        broadcast_userlist_update(manager, msg['room_id'], federation, local_server_addr)
    elif msg_type == ROOM_MESSAGE:
        # {type, room_id, message}
        manager.add_message(msg['room_id'], msg['message'])
        # Broadcast to all members INCLUDING sender
        members = manager.get_members(msg['room_id'])
        if members:
            print(f"[ROOM-SERVER-DEBUG] Broadcasting message to members: {members}, msg_id={msg['message'].get('msg_id')}")
            for member_id in members:
                print(f"[ROOM-SERVER-DEBUG] send_func({member_id}, ...)")
                send_func(member_id, {'type': ROOM_MESSAGE, 'room_id': msg['room_id'], 'message': msg['message']})
        # --- Federation: send to remote servers ---
        if federation and local_server_addr:
            userlist = manager.get_userlist(msg['room_id'])
            if userlist:
                for server_addr in userlist:
                    if server_addr != local_server_addr:
                        try:
                            host, port = server_addr.split(':')
                            port = int(port)
                            federation.send_message(server_addr, port, {
                                'type': 'federated_room_message',
                                'room_id': msg['room_id'],
                                'message': msg['message']
                            }, plaintext=True)
                        except Exception as e:
                            print(f"[ROOM-SERVER-DEBUG] Failed to federate room message to {server_addr}: {e}")
    elif msg_type == ROOM_HISTORY_REQUEST:
        # {type, room_id}
        history = manager.get_history(msg['room_id'])
        send_func(sender_id, {'type': ROOM_HISTORY_RESPONSE, 'room_id': msg['room_id'], 'history': history})
    elif msg_type == ROOM_FILE_OFFER:
        # {type, room_id, file_offer}
        members = manager.get_members(msg['room_id'])
        if members:
            for member_id in members:
                if member_id != sender_id:
                    send_func(member_id, {'type': ROOM_FILE_OFFER, 'room_id': msg['room_id'], 'file_offer': msg['file_offer']})
    # Add more handlers as needed (invites, etc.) 

# --- Federation: userlist resync ---
def send_userlist_request(manager, room_id, federation, local_server_addr):
    userlist = manager.get_userlist(room_id)
    for server_addr in userlist:
        if server_addr != local_server_addr:
            try:
                host, port = server_addr.split(':')
                port = int(port)
                federation.send_message(server_addr, port, {
                    'type': 'federated_room_userlist_request',
                    'room_id': room_id
                }, plaintext=True)
                break  # Only need to ask one server
            except Exception as e:
                print(f"[ROOM-SERVER-DEBUG] Failed to send userlist request to {server_addr}: {e}")

def handle_userlist_request(manager, msg, federation, local_server_addr):
    room_id = msg.get('room_id')
    userlist = manager.get_userlist(room_id)
    if userlist:
        try:
            host, port = msg.get('from_addr', '').split(':')
            port = int(port)
            federation.send_message(msg.get('from_addr'), port, {
                'type': 'federated_room_userlist_response',
                'room_id': room_id,
                'userlist': list(userlist)
            }, plaintext=True)
        except Exception as e:
            print(f"[ROOM-SERVER-DEBUG] Failed to send userlist response: {e}")

def handle_userlist_response(manager, msg):
    room_id = msg.get('room_id')
    userlist = set(msg.get('userlist', []))
    manager.merge_userlist(room_id, userlist) 

# --- Federation: history resync ---
def send_history_request(manager, room_id, federation, local_server_addr):
    userlist = manager.get_userlist(room_id)
    for server_addr in userlist:
        if server_addr != local_server_addr:
            try:
                host, port = server_addr.split(':')
                port = int(port)
                federation.send_message(server_addr, port, {
                    'type': 'federated_room_history_request',
                    'room_id': room_id
                }, plaintext=True)
                break  # Only need to ask one server
            except Exception as e:
                print(f"[ROOM-SERVER-DEBUG] Failed to send history request to {server_addr}: {e}")

def handle_history_request(manager, msg, federation, local_server_addr):
    room_id = msg.get('room_id')
    history = manager.get_history(room_id)
    if history:
        try:
            host, port = msg.get('from_addr', '').split(':')
            port = int(port)
            federation.send_message(msg.get('from_addr'), port, {
                'type': 'federated_room_history_response',
                'room_id': room_id,
                'history': history
            }, plaintext=True)
        except Exception as e:
            print(f"[ROOM-SERVER-DEBUG] Failed to send history response: {e}")

def handle_history_response(manager, msg):
    room_id = msg.get('room_id')
    incoming = msg.get('history', [])
    # Deduplicate by msg_id
    room = manager.get_room(room_id)
    if not room:
        return
    seen = {m.get('msg_id') for m in room.history if isinstance(m, dict)}
    for m in incoming:
        mid = m.get('msg_id')
        if mid and mid not in seen:
            room.history.append(m)
            seen.add(mid)
    if len(room.history) > 1000:
        room.history = room.history[-1000:]
    manager.save_rooms() 