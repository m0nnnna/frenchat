import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend

# --- RSA Key Management ---
def generate_rsa_keypair(bits=2048):
    """Generate a new RSA private/public key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=bits,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def save_private_key(private_key, filename):
    """Save a private key to a PEM file."""
    with open(filename, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

def save_public_key(public_key, filename):
    """Save a public key to a PEM file."""
    with open(filename, 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def load_private_key(filename):
    """Load a private key from a PEM file."""
    with open(filename, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

def load_public_key(filename):
    """Load a public key from a PEM file."""
    with open(filename, 'rb') as f:
        return serialization.load_pem_public_key(f.read(), backend=default_backend())

def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

def deserialize_public_key(pem_str):
    return serialization.load_pem_public_key(pem_str.encode('utf-8'), backend=default_backend())

def serialize_private_key(private_key):
    """Serialize a private key to PEM bytes."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

# --- RSA Encryption/Decryption ---
def rsa_encrypt(public_key, message_bytes):
    return public_key.encrypt(
        message_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_decrypt(private_key, ciphertext):
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# --- Fernet Symmetric Encryption ---
def generate_fernet_key():
    return Fernet.generate_key()

def get_fernet(key):
    return Fernet(key)

def fernet_encrypt(fernet, message_bytes):
    return fernet.encrypt(message_bytes)

def fernet_decrypt(fernet, token):
    return fernet.decrypt(token) 