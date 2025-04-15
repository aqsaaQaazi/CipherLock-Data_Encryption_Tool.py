# Imports
import streamlit as st;
import hashlib;
from cryptography.fernet import Fernet;


# -----------------------------FUNCTIONALITY-------------------------


# Production 
# Keys

KEY = Fernet.generate_key();
cipher = Fernet(KEY);

# dict for storage
stored_data: dict = {};
failed_attempts: int = 0;

# hashing Function;
"""
    Hash the given passkey using SHA-256.
    This ensures we never store the original passkey.
"""
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest();

# Fernet Encrypt
"""
    Encrypt the input text using Fernet.
    Returns the encrypted string in UTF-8 format.
"""
def encrypt_data(text, passkey):
    return cipher.encrypt(text.encode()).decode()

# Fernet Decrypt
def decrypt_data(encrypted_text, passkey):
    """
    Decrypts the encrypted data only if passkey matches.
    Returns decrypted text or None if the passkey is wrong.
    Locks after 3 failed attempts.
    """
    global failed_attempts
    hashed_passkey = hash_passkey(passkey)
    
# passkey validation
    for key, value in stored_data.items():
        if value["encrypted_text"] == encrypted_text and value["passkey"] == hashed_passkey:
            failed_attempts = 0;
            return cipher.decrypt(encrypted_text.encode()).decode;
    failed_attempts += 1;
    return None;


# _--------------------------------UI----------------------
tab1, tab2, tab3, tab4 = st.tabs(
    [
        "Home", 
        "Store Data", 
        "Retrieve Data", 
        "Login"
    ]
)

# HomePage
with tab1:
    st.title("CipherLock");
    st.subheader("Your Secure Data Vault");
    st.write("Securely store and retrieve your secrets with just a passkey — no database, no leaks, just pure encryption magic..");
    st.markdown("""
    - Encrypt any message using a secret passkey.  
    - Your data is stored only in memory.  
    - Only you can decrypt it with the right key.  
    - After 3 failed tries, you'll be asked to log in again for safety.  
    """)

# Store Data Page
with tab2:
    st.title("Store Your Secret");
    st.write("Enter the message you want to keep safe and your secret passkey.");
    
    # user input fields
    user_data = st.text_area("Enter Data:");
    passkey = st.text_input("Enter your secret passkey:", type="password");

    # Save button
    if st.button("Encrypt & Save"):
        if user_data and passkey:
            st.success("Data Secured!");
            
            hashed_passkey = hash_passkey(passkey);
            encrypted_text = encrypt_data(user_data, passkey);

            # Store
            stored_data[encrypted_text] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_passkey
            };

        else:
            st.error("Both fields are required!");

# Retrieve data
with tab3:
    st.title("Retrieve Secured Data!");
    st.write("Enter your encrypted message and passkey to decrypt it.");

    encrypted_text = st.text_area("Encrypted Message:");
    passkey = st.text_input("Passkey:", type="password");

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            decrypted_text = decrypt_data(encrypted_text, passkey);

            if decrypted_text:
                st.success(f"Decrypted Message: {decrypted_text}");
            else:
                st.error(f"Incorrect passkey! Attempts remaining: {3 - failed_attempts}")

                #if 3 failed attempts
                if failed_attempts >= 3:
                    st.warning("Too many failed attempts. Redirecting to Login page.")
                    st.experimental_rerun()
        else:
            st.error("Both Fields are required!");


# login
with tab4:
    st.subheader("Reauthorization Required");
    st.write("You've reached the login wall after 3 failed tries. Please enter the master password.")
    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":  # Demo password,
            failed_attempts = 0
            st.success("✅ Reauthorized successfully! \n Redirecting...")
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect password!")