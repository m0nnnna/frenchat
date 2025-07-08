"""
client_chat.py - Chat management for federated chat client
"""
import datetime

class ChatManager:
    def __init__(self, client_id):
        self.client_id = client_id
        self.active_chats = {}  # user_id -> list of messages
        self.current_chat_user = None

    def add_chat_message(self, user_id, sender, message):
        """Add a message to the chat history for a user."""
        if user_id not in self.active_chats:
            self.active_chats[user_id] = []
        timestamp = datetime.datetime.now().strftime("%H:%M")
        formatted_msg = f"[{timestamp}] {sender}: {message}"
        self.active_chats[user_id].append(formatted_msg)

    def get_chat_history(self, user_id):
        """Get the chat history for a user."""
        return self.active_chats.get(user_id, [])

    def set_current_chat_user(self, user_id):
        self.current_chat_user = user_id

    def get_current_chat_user(self):
        return self.current_chat_user

    def clear_chat_history(self, user_id=None):
        if user_id:
            self.active_chats[user_id] = []
        else:
            self.active_chats = {} 