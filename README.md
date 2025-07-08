# Federated Peer-to-Peer Chat Application

A secure, federated chat application where each user runs their own server+client combination, forming a decentralized network of interconnected chat servers.

## How It Works

**Federated Architecture**: Each user runs their own server and client on their workstation. These servers can connect to each other to form a federated network, allowing users to chat across different servers.

### Network Structure
```
User A (192.168.0.100:8443) ←→ User B (192.168.0.101:8443) ←→ User C (domain.com:443)
     ↓                              ↓                              ↓
  Server A                      Server B                      Server C
  Client A                      Client B                      Client C
```

- **Each user** runs their own server+client combination
- **Servers communicate** with each other to relay messages
- **Works with** local IPs, public IPs, or domains (including Cloudflare)
- **Port 443** for domains, custom ports for IPs
- **Self-hosted** - no central server required

## Features

- **Federated Network**: Servers connect to each other to form a decentralized network
- **Secure Communication**: All messages encrypted with RSA encryption
- **Peer-to-Peer Chat**: Direct client-to-client messaging through federated servers
- **Connection Approval**: GUI dialogs for accepting/rejecting chat requests
- **Real-time Chat Windows**: Separate chat windows for each conversation
- **File Transfer**: Secure file sharing between clients
- **Cross-Server Chat**: Chat with users on other federated servers
- **TLS/SSL Security**: Encrypted connections between servers and clients

## Installation

1. Install Python dependencies:
```bash
pip install cryptography pyopenssl
```

2. Configure your server and client:
   - Edit `config.conf` to set your server host, port, and client ID
   - The server will automatically generate SSL certificates

## Usage

### Starting Your Server+Client

**Normal operation** (recommended):
```bash
python chat_app.py
```

**Or use the test script**:
```bash
python test_chat.py
```
Choose option 3: "Start server + client (normal operation)"

### Connecting to Other Servers

1. **Get server details** from other users:
   - Host (IP or domain)
   - Port (443 for domains, custom for IPs)
   - Server ID (their client ID)

2. **Connect via GUI**:
   - Enter the host, port, and server ID in the "Federated Servers" section
   - Click "Connect to Server"

3. **Chat across servers**:
   - Users on different servers will appear in your client list
   - Request chats normally - messages are routed through the federated network

### Using the Chat Interface

1. **Connect to other servers** using the federated servers section
2. **View online clients** from all connected servers
3. **Request chat** with any user (local or federated)
4. **Approve/reject** chat requests via GUI dialog
5. **Chat** in dedicated windows with timestamps

## Configuration

Edit `config.conf`:
```ini
[Network]
host = 192.168.0.98  # Your server IP or domain
port = 8443          # Your server port (443 for domains)
client_id = alice    # Your unique client/server ID
```

### Network Configuration Examples

**Local Network**:
```ini
host = 192.168.0.100
port = 8443
client_id = alice
```

**Public IP**:
```ini
host = 203.0.113.10
port = 8443
client_id = bob
```

**Domain with Cloudflare**:
```ini
host = chat.example.com
port = 443
client_id = charlie
```

## Testing with Multiple Servers

Use the test script to create multiple federated servers:

```bash
python test_chat.py
```

Choose option 4: "Create configs for multiple federated servers"

This will create config files for multiple servers on different ports. Then:

1. **Start each server** in separate terminals
2. **Connect servers** to each other using the GUI
3. **Test cross-server chat** between users on different servers

## Commands

- **Request Chat**: Select a client and click "Request Chat"
- **Connect to Server**: Use the federated servers section to connect to other servers
- **Send File**: Click "Send File" to send files
- **List Commands**: Click "List Commands" to see available commands
- **Refresh Clients**: Click "Refresh Clients" to update the online client list

## Security Features

- **RSA Encryption**: All messages encrypted with 2048-bit RSA keys
- **TLS/SSL**: Secure connections between servers and clients
- **Key Verification**: Clients verify server keys to prevent man-in-the-middle attacks
- **Connection Approval**: Users must explicitly approve chat requests
- **Federated Security**: Each server manages its own security and keys
- **No Central Authority**: Decentralized network with no single point of failure

## Network Topology

The federated network can form various topologies:

```
Star Topology:
    Server A
   /    |    \
Server B  Server C  Server D

Mesh Topology:
Server A ←→ Server B ←→ Server C
   ↕         ↕         ↕
Server D ←→ Server E ←→ Server F
```

- **Direct connections** between servers
- **Message routing** through the network
- **Automatic discovery** of users on connected servers
- **Resilient** - if one server goes down, others can still communicate

## Troubleshooting

### Connection Issues
- Check that the target server is running
- Verify host, port, and server ID are correct
- Ensure firewall allows the connection
- For domains, ensure DNS resolution works

### Certificate Issues
- Delete `server.crt` and `server.key` to regenerate certificates
- For first connections, certificate verification is disabled
- Each server generates its own certificates

### Federation Issues
- Ensure both servers are online
- Check that server IDs are unique
- Verify network connectivity between servers
- Check server logs for connection errors

## Example Workflow

1. **Alice starts her server**: `python chat_app.py` (client_id = "alice")
2. **Bob starts his server**: `python chat_app.py` (client_id = "bob")
3. **Alice connects to Bob's server**:
   - Host: 192.168.0.101
   - Port: 8443
   - Server ID: bob
4. **Bob connects to Alice's server**:
   - Host: 192.168.0.100
   - Port: 8443
   - Server ID: alice
5. **Alice requests chat with Bob**: Select "bob" from client list
6. **Bob approves**: Click "Accept" in the popup dialog
7. **Chat window opens**: Both users get a dedicated chat window
8. **Messages are routed** through the federated network

## Advanced Usage

### Running Server Only
For testing or headless operation:
```bash
python test_chat.py
```
Choose option 1: "Start server only"

### Running Client Only
To connect to an existing server:
```bash
python test_chat.py
```
Choose option 2: "Start client only"

### Multiple Users per Server
Each server can have multiple local clients connected to it. The server acts as a hub for its local users and routes messages to other federated servers.

## Security Notes

- **Keep private keys secure** - they're stored in `server_private_key.pem`
- **Verify server certificates** on first connection
- **Only accept chat requests** from trusted users
- **Servers act as relays** but cannot decrypt messages
- **All encryption is end-to-end** between clients
- **Each server is autonomous** - no central authority required 