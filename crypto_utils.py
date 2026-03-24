import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend

# RSA Constants
RSA_KEY_SIZE = 2048
RSA_CHUNK_SIZE = 150 # Safe chunk size for 2048 bit with OAEP SHA-256
RSA_CIPHER_CHUNK_SIZE = 256 # Cipher block size for 2048 bit RSA

def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_SIZE,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def public_key_to_pem(public_key) -> str:
    """Serialize public key to a PEM string to be sent over the socket"""
    pemBytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pemBytes.decode('utf-8')

def pem_to_public_key(pem_string: str):
    """Deserialize a PEM string back to a public key object"""
    return serialization.load_pem_public_key(
        pem_string.encode('utf-8'),
        backend=default_backend()
    )

def encrypt_aes(key: bytes, message: str):
    """Encrypt message using AES-256 CBC with PKCS7 Padding"""
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(message.encode('utf-8')) + padder.finalize()
    
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    
    encrypted_data = iv + encrypted
    encoded = base64.b64encode(encrypted_data).decode('utf-8')
    return encoded, len(message), len(encoded)

def decrypt_aes(key: bytes, encoded_data: str) -> str:
    """Decrypt AES-256 CBC message and remove PKCS7 padding"""
    try:
        data = base64.b64decode(encoded_data.encode('utf-8'))
        iv = data[:16]
        ciphertext = data[16:]
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
        message_bytes = unpadder.update(padded_data) + unpadder.finalize()
        
        return message_bytes.decode('utf-8')
    except Exception as e:
        return f"<AES Decryption failed: {e}>"

def encrypt_rsa(public_key, message: str):
    """Encrypt message using RSA OAEP. Handles long messages via chunking."""
    message_bytes = message.encode('utf-8')
    original_size = len(message_bytes)
    encrypted_chunks = []
    
    for i in range(0, len(message_bytes), RSA_CHUNK_SIZE):
        chunk = message_bytes[i:i+RSA_CHUNK_SIZE]
        encrypted_chunk = public_key.encrypt(
            chunk,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        encrypted_chunks.append(encrypted_chunk)
        
    final_bytes = b''.join(encrypted_chunks)
    encoded = base64.b64encode(final_bytes).decode('utf-8')
    return encoded, original_size, len(encoded)

def decrypt_rsa(private_key, encoded_data: str) -> str:
    """Decrypt RSA OAEP message via chunking."""
    try:
        final_bytes = base64.b64decode(encoded_data.encode('utf-8'))
        decrypted_chunks = []
        
        for i in range(0, len(final_bytes), RSA_CIPHER_CHUNK_SIZE):
            chunk = final_bytes[i:i+RSA_CIPHER_CHUNK_SIZE]
            decrypted_chunk = private_key.decrypt(
                chunk,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            decrypted_chunks.append(decrypted_chunk)
            
        return b''.join(decrypted_chunks).decode('utf-8')
    except Exception as e:
        return f"<RSA Decryption failed: {e}>"
