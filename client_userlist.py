"""
client_userlist.py - User list management for federated chat client
"""
import datetime

class UserListManager:
    def __init__(self, client_id):
        self.client_id = client_id
        self.all_users = []
        self.known_users = {}
        self.display_to_user = {}
        self.user_credentials = {}

    def add_or_update_user(self, user):
        """Add or update a user in the list, avoiding duplicates."""
        user_id = user.get('user_id')
        if not user_id or user_id == self.client_id:
            return
        for i, u in enumerate(self.all_users):
            if u.get('user_id') == user_id:
                self.all_users[i].update(user)
                return
        self.all_users.append(user)

    def remove_user(self, user_id):
        self.all_users = [u for u in self.all_users if u.get('user_id') != user_id]

    def deduplicate(self):
        seen = set()
        unique = []
        for user in self.all_users:
            user_id = user.get('user_id')
            if user_id and user_id not in seen:
                seen.add(user_id)
                unique.append(user)
        self.all_users = unique

    def update_display_mapping(self):
        self.display_to_user = {}
        display_index = 0
        for user in self.all_users:
            if user.get('user_id') != self.client_id:
                self.display_to_user[display_index] = user
                display_index += 1

    def get_display_users(self):
        return [u for u in self.all_users if u.get('user_id') != self.client_id]

    def load_known_users(self, known_users):
        self.known_users = known_users.copy() if known_users else {}
        for user_id, info in self.known_users.items():
            if user_id != self.client_id:
                self.add_or_update_user({
                    'user_id': user_id,
                    'server': info.get('server', 'unknown'),
                    'public_key': info.get('public_key', 'unknown'),
                })
        self.deduplicate()

    def save_known_users(self):
        return self.known_users.copy()

    def update_known_users(self):
        for user in self.all_users:
            user_id = user.get('user_id')
            if user_id and user_id != self.client_id:
                self.known_users[user_id] = {
                    'server': user.get('server', 'unknown'),
                    'public_key': user.get('public_key', 'unknown'),
                    'last_seen': datetime.datetime.now().isoformat()
                }

    def clear(self):
        self.all_users = []
        self.display_to_user = {} 