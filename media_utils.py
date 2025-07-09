import os
import mimetypes
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- File Encryption/Decryption ---
def encrypt_file(input_path, output_path, key=None):
    """
    Encrypts a file with AES-GCM. Generates a random 32-byte key and 12-byte nonce if not provided.
    Stores nonce at the start of the output file. Returns (key, nonce).
    """
    if key is None:
        key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(key)
    with open(input_path, 'rb') as f:
        data = f.read()
    ct = aesgcm.encrypt(nonce, data, None)
    with open(output_path, 'wb') as f:
        f.write(nonce + ct)
    return key, nonce

def decrypt_file(input_path, output_path, key, nonce=None):
    """
    Decrypts a file with AES-GCM. If nonce is None, reads the first 12 bytes from the file.
    """
    with open(input_path, 'rb') as f:
        if nonce is None:
            nonce = f.read(12)
            ct = f.read()
        else:
            ct = f.read()
    aesgcm = AESGCM(key)
    data = aesgcm.decrypt(nonce, ct, None)
    with open(output_path, 'wb') as f:
        f.write(data)
    return True

def encrypt_bytes(data: bytes, key=None):
    """
    Encrypts bytes with AES-GCM. Returns (ciphertext, key, nonce).
    """
    if key is None:
        key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, data, None)
    return ct, key, nonce

def decrypt_bytes(ciphertext: bytes, key, nonce):
    """
    Decrypts bytes with AES-GCM. Returns plaintext bytes.
    """
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)

def generate_file_metadata(path):
    """
    Returns a dict with filename, size, and mimetype for the given file path.
    """
    filename = os.path.basename(path)
    size = os.path.getsize(path)
    mimetype, _ = mimetypes.guess_type(path)
    return {
        'filename': filename,
        'size': size,
        'mimetype': mimetype or 'application/octet-stream'
    }

def generate_thumbnail(path):
    """
    (Optional) Generates a thumbnail for image/video files. Stub for now.
    Returns None.
    """
    return None 