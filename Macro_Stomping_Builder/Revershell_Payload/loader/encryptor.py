"""
AES-256-GCM Shellcode Encryptor
"""
import os
import sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

default_password = "NT230_Group5_Key"

def generate_key_from_password(password: str, salt: bytes = None) -> tuple:
    """Generate AES key from password using PBKDF2"""
    if salt is None:
        salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(password.encode())
    return key, salt

def encrypt_shellcode(shellcode: bytes, password: str) -> dict:
    """
    Encrypt shellcode using AES-256-GCM
    """
    key, salt = generate_key_from_password(password)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    encrypted = aesgcm.encrypt(nonce, shellcode, None)
    
    return {
        'encrypted_data': encrypted,
        'nonce': nonce,
        'salt': salt,
    }

def save_encrypted_shellcode(encrypted_dict: dict, output_file: str):
    """
    Save encrypted shellcode to file
    Format: SALT(16) + NONCE(12) + ENCRYPTED_DATA
    """
    with open(output_file, 'wb') as f:
        f.write(encrypted_dict['salt'])
        f.write(encrypted_dict['nonce'])
        f.write(encrypted_dict['encrypted_data'])

def load_encrypted_shellcode(input_file: str) -> dict:
    with open(input_file, 'rb') as f:
        data = f.read()
    
    return {
        'salt': data[:16],
        'nonce': data[16:28],
        'encrypted_data': data[28:]
    }

def main():
    if len(sys.argv) < 3:
        print("Usage:")
        print("  Encrypt: python encryptor.py <input.bin> <output.bin> [password]")
        sys.exit(1)
        
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    password = sys.argv[3] if len(sys.argv) > 3 else default_password
    
    with open(input_file, 'rb') as f:
        shellcode = f.read()
    
    encrypted_dict = encrypt_shellcode(shellcode, password)
    save_encrypted_shellcode(encrypted_dict, output_file)
    print(f"[+] Encrypted shellcode saved to: {output_file}")

if __name__ == "__main__":
    main()
