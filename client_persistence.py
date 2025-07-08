"""
client_persistence.py - Persistence management for federated chat client
"""
import json
import os

class PersistenceManager:
    def __init__(self, client_id):
        self.client_id = client_id

    def load_json(self, filename, default=None):
        try:
            with open(filename, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return default if default is not None else {}
        except Exception as e:
            print(f"[Persistence] Error loading {filename}: {e}")
            return default if default is not None else {}

    def save_json(self, filename, data):
        try:
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"[Persistence] Error saving {filename}: {e}")

    def load_known_users(self):
        return self.load_json(f'known_users_{self.client_id}.json', {})

    def save_known_users(self, known_users):
        self.save_json(f'known_users_{self.client_id}.json', known_users)

    def load_known_rooms(self):
        return self.load_json(f'known_rooms_{self.client_id}.json', {})

    def save_known_rooms(self, known_rooms):
        self.save_json(f'known_rooms_{self.client_id}.json', known_rooms)

    def load_federated_servers(self):
        servers = self.load_json(f'federated_servers_{self.client_id}.json', [])
        return set(servers)

    def save_federated_servers(self, federated_servers):
        self.save_json(f'federated_servers_{self.client_id}.json', list(federated_servers))

    def load_user_credentials(self):
        return self.load_json(f'user_credentials_{self.client_id}.json', {})

    def save_user_credentials(self, user_credentials):
        self.save_json(f'user_credentials_{self.client_id}.json', user_credentials)

    def load_room_history(self):
        return self.load_json(f'room_history_{self.client_id}.json', {'rooms': {}, 'members': {}})

    def save_room_history(self, active_rooms, room_members):
        room_data = {
            'rooms': active_rooms,
            'members': {room: list(members) for room, members in room_members.items()}
        }
        self.save_json(f'room_history_{self.client_id}.json', room_data) 