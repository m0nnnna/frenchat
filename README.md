# Federated Peer-to-Peer Chat Application

A secure, federated chat application where each user runs their own server+client combination, forming a decentralized network of interconnected chat servers with end-to-end encrypted messaging and file transfers.

## How It Works

**Federated Architecture**: Each user runs their own server and client on their workstation. These servers can connect to each other to form a federated network, allowing users to chat across different servers with full end-to-end encryption.

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
- **End-to-end encrypted** - messages and files are encrypted between clients

## Features

### Core Chat Features
- **Federated Network**: Servers connect to each other to form a decentralized network
- **End-to-End Encryption**: All messages encrypted with RSA-2048 encryption
- **Peer-to-Peer Chat**: Direct client-to-client messaging through federated servers
- **Contact Management**: Add, remove, and manage contacts with approval workflows
- **Real-time Chat**: Instant messaging with message history
- **Cross-Server Chat**: Chat with users on other federated servers
- **TLS/SSL Security**: Encrypted connections between servers and clients

### File Transfer System
- **Secure File Sharing**: End-to-end encrypted file transfers between clients
- **File Approval Workflow**: Popup dialogs for accepting/declining file transfers
- **Progress Tracking**: Real-time progress bars showing download progress
- **Large File Support**: Chunked transfer system supporting files up to 99MB per chunk
- **Multiple File Types**: Support for any file type (images, videos, documents, etc.)
- **File Completion Notifications**: Popup notifications when downloads complete
- **Clickable File Links**: Direct file opening from chat interface

### Security & Privacy
- **Password-Protected Chat History**: AES-encrypted local chat history with password protection
- **UI Lock Feature**: Lock the interface with password protection
- **Contact Approval**: GUI dialogs for accepting/rejecting contact requests
- **Key Verification**: Clients verify server keys to prevent man-in-the-middle attacks
- **Federated Security**: Each server manages its own security and keys
- **No Central Authority**: Decentralized network with no single point of failure

### User Interface
- **Modern PyQt6 Interface**: Clean, responsive GUI with proper dialogs
- **Non-blocking Popups**: All dialogs are non-modal, allowing continued app usage
- **Contact List Management**: Right-click context menus for contact actions
- **Unread Message Counts**: Visual indicators for unread messages
- **Chat History Persistence**: Automatic saving and loading of chat conversations

## Installation

1. Install Python dependencies:
```bash
pip install cryptography pyopenssl PyQt6
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

### Adding Contacts

1. **Add Contact**: Click the 3 line menu then "Add Contact" and enter the server address (host:port)
2. **Contact Request**: The other user will receive a contact request popup
3. **Key Approval**: If it's a new contact, approve their public key
4. **Contact Added**: The contact appears in your contact list

### File Transfer

1. **Attach File**: Click the paperclip icon to select a file
2. **File Offer**: The recipient receives a popup asking to accept/decline
3. **Accept/Decline**: Recipient can accept or decline the file transfer
4. **Progress Tracking**: If accepted, a progress bar shows download progress
5. **Completion**: Popup notification when download completes
6. **Open File**: Click the file link in chat to open the downloaded file

### Chat Interface

1. **Select Contact**: Click on a contact in the contact list
2. **Send Messages**: Type in the message box and press Enter or click Send
3. **View History**: Chat history is automatically loaded and displayed
4. **File Attachments**: Use the paperclip icon to send files
5. **Remove Contacts**: Right-click a contact and select "Remove" to delete

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

### Network Configuration Examples

**Local Network**:
```ini
[Network]
host = 192.168.0.98
port = 8443
public_ip = 
```

**Public IP** (if you want your server to be directly accessible from the internet):
```ini
host = 192.168.0.100  
port = 8443           
public_ip = 203.0.113.10  
```

**Domain with nginx (recommended for domains):**
```ini
host = 192.168.0.98    
port = 8443
public_ip =           
# public_ip not needed
```
Set up nginx (or another reverse proxy) to forward traffic from your domain to your local server as described above in the 'Using a Domain or Domain with Proxy' section.

## File Transfer Protocol

The file transfer system uses a sophisticated protocol for secure, reliable transfers:

1. **File Offer**: Sender creates a file offer with metadata
2. **Approval**: Recipient approves/declines via popup dialog
3. **Encryption**: File is encrypted with AES-GCM using a random key
4. **Key Exchange**: AES key is encrypted with recipient's RSA public key
5. **Chunked Transfer**: File is sent in 99MB chunks with progress tracking
6. **Reassembly**: Recipient reassembles chunks and decrypts the file
7. **Completion**: File is ready for use with clickable links

### Security Features
- **AES-GCM Encryption**: Files encrypted with authenticated encryption
- **RSA Key Exchange**: AES keys encrypted with recipient's public key
- **Chunked Transfer**: Large files split into manageable chunks
- **Progress Tracking**: Real-time progress updates during transfer
- **Error Handling**: Robust error handling and recovery

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
4. **Test file transfers** across the federated network

## Commands

- **Add Contact**: Add new contacts to your contact list
- **Remove Contact**: Right-click to remove contacts and clear chat history
- **Send File**: Click the paperclip icon to send files
- **Lock UI**: Lock the interface with password protection
- **Refresh Contacts**: Update the contact list from the backend

## Security Features

- **RSA-2048 Encryption**: All messages encrypted with strong RSA encryption
- **AES-GCM File Encryption**: Files encrypted with authenticated encryption
- **TLS/SSL**: Secure connections between servers and clients
- **Key Verification**: Clients verify server keys to prevent man-in-the-middle attacks
- **Contact Approval**: Users must explicitly approve contact requests
- **Password Protection**: Chat history encrypted with user-provided password
- **Federated Security**: Each server manages its own security and keys
- **No Central Authority**: Decentralized network with no single point of failure
- **Chunked File Transfer**: Large files are split into manageable chunks for reliability
- **Progress Tracking**: Real-time progress updates during file transfer
- **Error Handling**: Robust error handling and recovery

### Network Configuration Examples

**Local Network**:
```ini
host = 192.168.0.100
port = 8443
# public_ip not needed
```

**Public IP** (if you want your server to be directly accessible from the internet):
```ini
host = 192.168.0.100  # Local IP of your machine
port = 8443           # Local port your server listens on
public_ip = 203.0.113.10  # Your public IP (used for federation)
```

**Domain with nginx (recommended for domains):**
```ini
host = 127.0.0.1      # Local IP (do not use your domain here)
port = 8443           # Local port your server listens on
# public_ip not needed
```
Set up nginx (or another reverse proxy) to forward traffic from your domain to your local server as described above in the 'Using a Domain or Domain with Proxy' section.

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

### File Transfer Issues
- Ensure both users are online
- Check file size limits (99MB per chunk)
- Verify network connectivity between servers
- Check server logs for transfer errors

### Federation Issues
- Ensure both servers are online
- Check that server IDs are unique
- Verify network connectivity between servers
- Check server logs for connection errors

## Example Workflow

1. **Alice starts her server**: `python chat_app.py` (client_id = "alice")
2. **Bob starts his server**: `python chat_app.py` (client_id = "bob")
3. **Alice adds Bob as contact**: Enter Bob's server address
4. **Bob approves contact request**: Accept Alice's contact request
5. **Alice sends a file**: Click paperclip, select file, Bob approves
6. **File transfers with progress**: Progress bar shows download progress
7. **Bob receives file**: Completion popup, file ready to open
8. **Chat across servers**: Messages routed through federated network

## Technical Details

### Encryption
- **RSA-2048**: For message encryption and key exchange
- **AES-GCM**: For file encryption with authentication
- **TLS/SSL**: For transport layer security

### File Transfer
- **Chunk Size**: 99MB per chunk for large file support
- **Progress Tracking**: Real-time progress updates
- **Error Recovery**: Automatic retry and error handling
- **Cleanup**: Temporary files automatically cleaned up

### Chat History
- **AES Encryption**: Chat history encrypted with user password
- **Automatic Saving**: Messages saved automatically
- **Persistent Storage**: Chat history survives application restarts
- **Contact-Specific**: Separate history for each contact 

## Using a Domain or Domain with Proxy

If you want to use a domain (e.g., `chat.example.com`) or run your server behind a proxy (such as nginx), you should:

- **Set your `config.conf` file to use your local IP and port** (e.g., `host = 127.0.0.1`, `port = 8443`).
- **Do not set the host to your public domain name in the conf file.**
- **Use nginx (or another reverse proxy)** to forward traffic from your domain (port 443 or 80) to your local server's IP and port.

Example nginx config:
```nginx
server {
    listen 443 ssl;
    server_name chat.example.com;

    ssl_certificate /path/to/fullchain.pem;
    ssl_certificate_key /path/to/privkey.pem;

    location / {
        proxy_pass https://127.0.0.1:8443;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

This allows you to keep your chat server running on a local IP and port, while making it accessible via your public domain securely through nginx. 