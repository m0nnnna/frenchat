#!/usr/bin/env python3
"""
Test script for the federated peer-to-peer chat application.
This script helps you test the federated chat functionality with multiple servers.
"""

import subprocess
import time
import sys
import os

def create_config(client_id, host="192.168.0.98", port="8443"):
    """Create a config file for a specific client"""
    config_content = f"""[Network]
host = {host}
port = {port}
client_id = {client_id}
"""
    config_file = f"config_{client_id}.conf"
    with open(config_file, 'w') as f:
        f.write(config_content)
    return config_file

def run_client(config_file):
    """Run a client with the specified config file"""
    # Temporarily rename the config file to config.conf
    original_config = "config.conf"
    if os.path.exists(original_config):
        os.rename(original_config, "config.conf.backup")
    
    os.rename(config_file, original_config)
    
    try:
        # Run the client
        subprocess.run([sys.executable, "chat_app.py"], check=True)
    except KeyboardInterrupt:
        print(f"\nClient stopped by user")
    except subprocess.CalledProcessError as e:
        print(f"Client failed with error: {e}")
    finally:
        # Restore original config
        os.rename(original_config, config_file)
        if os.path.exists("config.conf.backup"):
            os.rename("config.conf.backup", original_config)

def run_server_only(config_file):
    """Run only the server with the specified config file"""
    # Temporarily rename the config file to config.conf
    original_config = "config.conf"
    if os.path.exists(original_config):
        os.rename(original_config, "config.conf.backup")
    
    os.rename(config_file, original_config)
    
    try:
        # Run the server
        subprocess.run([sys.executable, "server.py"], check=True)
    except KeyboardInterrupt:
        print(f"\nServer stopped by user")
    except subprocess.CalledProcessError as e:
        print(f"Server failed with error: {e}")
    finally:
        # Restore original config
        os.rename(original_config, config_file)
        if os.path.exists("config.conf.backup"):
            os.rename("config.conf.backup", original_config)

def main():
    print("Federated Peer-to-Peer Chat Test Script")
    print("=" * 50)
    print()
    print("This script will help you test the federated chat functionality.")
    print("Each user runs their own server+client combination.")
    print("Servers can connect to each other to form a federated network.")
    print()
    
    # Get server details
    host = input("Enter your server host (default: 192.168.0.98): ").strip() or "192.168.0.98"
    port = input("Enter your server port (default: 8443): ").strip() or "8443"
    
    print()
    print("Available options:")
    print("1. Start server only (for testing)")
    print("2. Start client only (connect to existing server)")
    print("3. Start server + client (normal operation)")
    print("4. Create configs for multiple federated servers")
    print("5. Exit")
    
    while True:
        choice = input("\nEnter your choice (1-5): ").strip()
        
        if choice == "1":
            client_id = input("Enter server/client ID: ").strip()
            if not client_id:
                print("Server ID cannot be empty")
                continue
            
            config_file = create_config(client_id, host, port)
            print(f"\nStarting server only with ID '{client_id}'...")
            run_server_only(config_file)
        
        elif choice == "2":
            client_id = input("Enter client ID: ").strip()
            if not client_id:
                print("Client ID cannot be empty")
                continue
            
            config_file = create_config(client_id, host, port)
            print(f"\nStarting client only with ID '{client_id}'...")
            run_client(config_file)
        
        elif choice == "3":
            client_id = input("Enter server/client ID: ").strip()
            if not client_id:
                print("Server/client ID cannot be empty")
                continue
            
            config_file = create_config(client_id, host, port)
            print(f"\nStarting server + client with ID '{client_id}'...")
            run_client(config_file)
        
        elif choice == "4":
            print("\nThis will create config files for multiple federated servers.")
            print("Each server can run on different machines or ports.")
            
            num_servers = input("How many federated servers do you want to create configs for? (default: 3): ").strip()
            try:
                num_servers = int(num_servers) if num_servers else 3
            except ValueError:
                num_servers = 3
            
            print(f"\nCreating config files for {num_servers} federated servers...")
            
            # Create different configs for each server
            for i in range(1, num_servers + 1):
                server_id = f"server{i}"
                server_host = host
                server_port = int(port) + i - 1  # Different ports for each server
                
                config_file = create_config(server_id, server_host, server_port)
                print(f"Created config for {server_id}: {config_file} (host: {server_host}, port: {server_port})")
            
            print(f"\nTo test the federated network:")
            print("1. Start each server in separate terminals:")
            for i in range(1, num_servers + 1):
                server_id = f"server{i}"
                server_port = int(port) + i - 1
                print(f"   Terminal {i}: python test_chat.py (choose option 1, enter '{server_id}')")
            
            print("\n2. Connect servers to each other using the GUI:")
            print("   - In each client, use the 'Federated Servers' section")
            print("   - Enter host, port, and server ID of other servers")
            print("   - Click 'Connect to Server'")
            
            print("\n3. Test cross-server chat:")
            print("   - Request chats between clients on different servers")
            print("   - Messages will be routed through the federated network")
        
        elif choice == "5":
            print("Goodbye!")
            break
        
        else:
            print("Invalid choice. Please enter 1-5.")

if __name__ == "__main__":
    main() 