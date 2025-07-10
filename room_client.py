from room_protocol import (
    ROOM_CREATE, ROOM_INVITE, ROOM_JOIN, ROOM_LEAVE, ROOM_MESSAGE,
    ROOM_HISTORY_REQUEST, ROOM_HISTORY_RESPONSE, ROOM_FILE_OFFER
)
from typing import Callable, Dict, List, Optional

class RoomClient:
    """
    Handles client-side logic for rooms. Integrate with your main client by:
    - Calling handle_incoming_room_message() for room-related messages
    - Using provided methods to create/join/leave rooms, send messages, request history, etc.
    - Registering callbacks for UI updates (on_room_update, on_room_message, on_file_offer, etc.)
    """
    def __init__(self, user_id: str, send_func: Callable[[dict], None]):
        self.user_id = user_id
        self.send_func = send_func  # Function to send a message to the server
        self.rooms: Dict[str, dict] = {}  # room_id -> room dict (from server)
        self.room_histories: Dict[str, List[dict]] = {}  # room_id -> list of messages
        # Callbacks for UI integration
        self.on_room_update = None  # (room_dict) -> None
        self.on_room_message = None  # (room_id, message_dict) -> None
        self.on_file_offer = None  # (room_id, file_offer_dict) -> None

    # --- Outgoing actions ---
    def create_room(self, name: str, is_private: bool, password: Optional[str] = None):
        msg = {'type': ROOM_CREATE, 'name': name, 'is_private': is_private}
        if is_private and password:
            msg['password'] = password
        self.send_func(msg)

    def join_room(self, room_id: str, password: Optional[str] = None):
        msg = {'type': ROOM_JOIN, 'room_id': room_id}
        if password:
            msg['password'] = password
        self.send_func(msg)

    def leave_room(self, room_id: str):
        msg = {'type': ROOM_LEAVE, 'room_id': room_id}
        self.send_func(msg)

    def send_room_message(self, room_id: str, message: dict):
        msg = {'type': ROOM_MESSAGE, 'room_id': room_id, 'message': message}
        self.send_func(msg)

    def request_room_history(self, room_id: str):
        msg = {'type': ROOM_HISTORY_REQUEST, 'room_id': room_id}
        self.send_func(msg)

    def offer_file_to_room(self, room_id: str, file_offer: dict):
        msg = {'type': ROOM_FILE_OFFER, 'room_id': room_id, 'file_offer': file_offer}
        self.send_func(msg)

    # --- Incoming message handler ---
    def handle_incoming_room_message(self, msg: dict):
        msg_type = msg.get('type')
        if msg_type == 'room_create_success':
            room = msg['room']
            self.rooms[room['room_id']] = room
            if self.on_room_update:
                self.on_room_update(room)
        elif msg_type == 'room_create_error':
            # Optionally handle error (show popup, etc.)
            pass
        elif msg_type == 'room_join_success':
            room = msg['room']
            self.rooms[room['room_id']] = room
            self.request_room_history(room['room_id'])
            if self.on_room_update:
                self.on_room_update(room)
        elif msg_type == 'room_join_error':
            # Optionally handle error (show popup, etc.)
            pass
        elif msg_type == 'room_leave_success':
            room_id = msg['room_id']
            if room_id in self.rooms:
                del self.rooms[room_id]
            if room_id in self.room_histories:
                del self.room_histories[room_id]
            if self.on_room_update:
                self.on_room_update({'room_id': room_id, 'left': True})
        elif msg_type == ROOM_MESSAGE:
            room_id = msg['room_id']
            message = msg['message']
            if room_id not in self.room_histories:
                self.room_histories[room_id] = []
            # Deduplicate by msg_id
            msg_ids = {m.get('msg_id') for m in self.room_histories[room_id] if isinstance(m, dict)}
            if message.get('msg_id') not in msg_ids:
                self.room_histories[room_id].append(message)
                if len(self.room_histories[room_id]) > 1000:
                    self.room_histories[room_id] = self.room_histories[room_id][-1000:]
            if self.on_room_message:
                self.on_room_message(room_id, message)
        elif msg_type == ROOM_HISTORY_RESPONSE:
            room_id = msg['room_id']
            history = msg['history']
            self.room_histories[room_id] = history or []
            if self.on_room_update:
                self.on_room_update(self.rooms.get(room_id, {'room_id': room_id}))
        elif msg_type == ROOM_FILE_OFFER:
            room_id = msg['room_id']
            file_offer = msg['file_offer']
            if self.on_file_offer:
                self.on_file_offer(room_id, file_offer)
        # Add more handlers as needed (invites, etc.)

    # --- Utility ---
    def get_room(self, room_id: str) -> Optional[dict]:
        return self.rooms.get(room_id)

    def get_room_history(self, room_id: str) -> List[dict]:
        return self.room_histories.get(room_id, [])

    def set_on_room_update(self, callback):
        self.on_room_update = callback

    def set_on_room_message(self, callback):
        self.on_room_message = callback

    def set_on_file_offer(self, callback):
        self.on_file_offer = callback 