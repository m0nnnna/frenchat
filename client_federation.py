"""
client_federation.py - Federation management for federated chat client
"""
import time

class FederationManager:
    def __init__(self, client_id):
        self.client_id = client_id
        self.federated_servers = set()
        self.server_status = {}  # server_id -> online/offline

    def add_federated_server(self, server_id):
        self.federated_servers.add(server_id)

    def remove_federated_server(self, server_id):
        self.federated_servers.discard(server_id)
        if server_id in self.server_status:
            del self.server_status[server_id]

    def set_server_status(self, server_id, is_online):
        self.server_status[server_id] = is_online

    def is_server_online(self, server_id):
        return self.server_status.get(server_id, False)

    def get_online_servers(self):
        return [sid for sid, online in self.server_status.items() if online]

    def get_all_servers(self):
        return list(self.federated_servers)

    def clear(self):
        self.federated_servers = set()
        self.server_status = {} 