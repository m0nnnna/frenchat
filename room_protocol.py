import hashlib
import os
import secrets
from typing import List, Set, Optional

# Message type constants
ROOM_CREATE = 'room_create'
ROOM_INVITE = 'room_invite'
ROOM_JOIN = 'room_join'
ROOM_LEAVE = 'room_leave'
ROOM_MESSAGE = 'room_message'
ROOM_HISTORY_REQUEST = 'room_history_request'
ROOM_HISTORY_RESPONSE = 'room_history_response'
ROOM_FILE_OFFER = 'room_file_offer'
FEDERATED_ROOM_JOIN_REQUEST = 'federated_room_join_request'
FEDERATED_ROOM_JOIN_RESPONSE = 'federated_room_join_response'


def generate_room_id() -> str:
    """Generate a unique, random room ID."""
    return secrets.token_hex(8)


def hash_password(password: str) -> str:
    """Hash a password for private rooms (SHA-256)."""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()


def check_password(password: str, password_hash: str) -> bool:
    """Check if a password matches the stored hash."""
    return hash_password(password) == password_hash


class Room:
    def __init__(self, room_id: str, name: str, is_private: bool, password_hash: Optional[str] = None):
        self.room_id = room_id
        self.name = name
        self.is_private = is_private
        self.password_hash = password_hash  # Only for private rooms
        self.members: Set[str] = set()  # user_ids
        self.history: List[dict] = []  # last 1000 messages (no files)
        self.userlist: Set[str] = set()  # set of server addresses

    def add_member(self, user_id: str):
        self.members.add(user_id)

    def remove_member(self, user_id: str):
        self.members.discard(user_id)

    def add_message(self, message: dict):
        self.history.append(message)
        if len(self.history) > 1000:
            self.history = self.history[-1000:]

    def to_dict(self):
        return {
            'room_id': self.room_id,
            'name': self.name,
            'is_private': self.is_private,
            'members': list(self.members),
            'history': self.history,
            'userlist': list(self.userlist),  # Always include userlist
        }

    @staticmethod
    def from_dict(data: dict):
        room = Room(
            room_id=data['room_id'],
            name=data['name'],
            is_private=data['is_private'],
            password_hash=data.get('password_hash')
        )
        room.members = set(data.get('members', []))
        room.history = data.get('history', [])
        room.userlist = set(data.get('userlist', []))  # Always initialize userlist
        return room 