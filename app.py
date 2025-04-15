# Imports
import streamlit as st;
import hashlib;
from cryptography.fernet import Fernet;


# Production 
# Keys

KEY = Fernet.generate_key();
cipher = Fernet(KEY);

# dict for storage
stored_data: dict = {};
failed_attempts: int = 0;

# hashing Function;
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest();

# Fernet Encrypt
def encrypt_data(text, passkey):
    return cipher.encrypt(text.encode()).decode()

# Fernet Decrypt
def decrypt_data(encrypted_text, passkey):
    global failed_attempts
    hashed_passkey = hash_passkey(passkey)
    
# passkey validation
    for key, value in stored_data.items():
        if value["encrypted_text"] == encrypted_text and value["passkey"] == hashed_passkey:
            failed_attempts = 0;
            return cipher.decrypt(encrypted_text.encode()).decode;
    failed_attempts += 1;
    return None;