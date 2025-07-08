import os
import configparser
import random
import threading
from server import ServerBackend, run_server
from client import ChatClientGUI

def generate_gemstone_username():
    gemstones = [
        "Amethyst", "Aquamarine", "Citrine", "Diamond", "Emerald", "Garnet", "Jade", "Jasper", "Lapis", "Malachite",
        "Moonstone", "Obsidian", "Onyx", "Opal", "Pearl", "Peridot", "Quartz", "Ruby", "Sapphire", "Topaz", "Tourmaline", "Turquoise"
    ]
    return random.choice(gemstones) + str(random.randint(1000, 9999))

def load_or_generate_username():
    username_file = "username.txt"
    if os.path.exists(username_file):
        with open(username_file, "r") as f:
            username = f.read().strip()
            if username:
                print(f"[DEBUG] Loaded existing username: {username}")
                return username
    # Generate and save new username
    username = generate_gemstone_username()
    with open(username_file, "w") as f:
        f.write(username)
    print(f"[DEBUG] Generated and saved new username: {username}")
    return username

config = configparser.ConfigParser()
config.read('config.conf')
local_ip = config['Network']['host']
public_ip = config['Network'].get('public_ip', '').strip() if 'public_ip' in config['Network'] else ''

san_list = [f"IP:{local_ip}"]
if public_ip:
    san_list.append(f"IP:{public_ip}")

if __name__ == "__main__":
    CLIENT_ID = load_or_generate_username()
    # Start the server in a background thread, passing CLIENT_ID
    server_thread = threading.Thread(target=run_server, args=(CLIENT_ID,), daemon=True)
    server_thread.start()
    # Start the client GUI, passing CLIENT_ID to the backend
    server_backend = ServerBackend(CLIENT_ID)
    gui = ChatClientGUI(server_backend, CLIENT_ID)
    gui.root.mainloop()