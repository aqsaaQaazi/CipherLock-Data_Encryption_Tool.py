# Imports
import streamlit as st;
import hashlib;
from cryptography.fernet import Fernet;
import os 

# ---------------------------------PAGe CONFIG-----------------------------
st.set_page_config(
    page_title="CipherLock | Aqsaa Qaazi",
    page_icon="🔐",
    layout="centered",
    initial_sidebar_state="auto")

# -----------------------------FUNCTIONALITY-------------------------

# ----------------------------Fernet Key Handling--------------------------
def load_fernet_key():
    """Load existing Fernet key or generate and save a new one."""
    
    if os.path.exists("secret.key"):
        with open("secret.key", "rb") as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open("secret.key", "wb") as f:
            f.write(key)
        return key

# Production 
# Keys

KEY = load_fernet_key()
cipher = Fernet(KEY)

# ----------------------------- Password Hashing -----------------------------

def hash_passkey(passkey):
    """Hash the passkey using SHA-256."""
    return hashlib.sha256(passkey.encode()).hexdigest()

MASTER_HASHED = hash_passkey("admin123")



# ---------------------------------IN MEMORY STORAGE--------------------------------
stored_data: dict = {};
failed_attempts: int = 0;


# -----------------------------Encryption & Decryption -----------------------------

def encrypt_data(text, passkey):
    """Encrypt the input text using Fernet."""
    return cipher.encrypt(text.encode()).decode()

# Fernet Decrypt
def decrypt_data(encrypted_text, passkey):
    """
    Attempt to decrypt only if passkey matches stored hash.
    Allows 3 attempts before locking.
    """
    global failed_attempts
    hashed_passkey = hash_passkey(passkey)

    # Validate against stored entries
    entry = stored_data.get(encrypted_text)
    if entry and entry["passkey"] == hashed_passkey:
        failed_attempts = 0
        return cipher.decrypt(encrypted_text.encode()).decode()

    failed_attempts += 1
    return None

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
    # st.title("CipherLock");
    # st.subheader("Your Secure Data Vault");
    # st.write("Securely store and retrieve your secrets with just a passkey — no database, no leaks, just pure encryption magic..");
    # st.markdown("""
    # - Encrypt any message using a secret passkey.  
    # - Your data is stored only in memory.  
    # - Only you can decrypt it with the right key.  
    # - After 3 failed tries, you'll be asked to log in again for safety.  
    # """)
    
    st.markdown("<h1 style='text-align: center; color: #4CAF50;'>🔐 CipherLock</h1>", unsafe_allow_html=True)
    st.markdown("<h3 style='text-align: center; color: #777;'>Your Secure Data Vault</h3>", unsafe_allow_html=True)

    st.write("")

    st.markdown(
        """
        <div style='text-align: center; font-size: 16px;'>
            CipherLock is a <strong>zero-database</strong>, <strong>memory-only</strong> encryption vault.<br>
            Store & retrieve sensitive info using just a passkey.<br><br>
            Everything stays local. No sign-up. No storage. Just <i>pure encryption magic</i>.
        </div>
        """,
        unsafe_allow_html=True
    )

    st.write("")
    st.divider()

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("How It Works?")
        st.markdown(
            """
            - Enter your message  
            - Lock it with a passkey  
            - Retrieve it only with the same passkey  
            - After 3 wrong tries? You're locked out 🔐
            """
        )

    with col2:
        st.subheader("Why Use It?")
        st.markdown(
            """
            - Lightweight, fast, and secure  
            - No account needed  
            - Perfect for quick secrets  
            - Great for demos or testing encrypted workflows  
            """
        )


    # st.subheader("👨‍💻 About the Developer")
    with st.expander("## About the Developer "):
        st.markdown(
            """
            **Aqsaa Qaazi** — a developer who loves building secure, snappy, and stylish tools.
            
            This project was built using **Streamlit**, **Fernet encryption**, and a dash of dedication ❤️.
            """
        )

    st.write("")

# Store Data Page
with tab2:
    st.header("Store Your Secret")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter your secret passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data, passkey)

            stored_data[encrypted_text] = {
                "passkey": hashed_passkey
            }

            st.success(" Data encrypted and stored successfully!")
            st.code(encrypted_text, language="text")
        else:
            st.error("Both fields are required.")
# Retrieve data
with tab3:
    st.header("Retrieve Your Data")
    encrypted_text = st.text_area("Paste Encrypted Message:")
    passkey = st.text_input("Enter your passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            decrypted_text = decrypt_data(encrypted_text, passkey)
            if decrypted_text:
                st.success("Decryption successful!")
                st.code(decrypted_text, language="text")
            else:
                st.error(f"Incorrect passkey! Attempts remaining: {3 - failed_attempts}")
                if failed_attempts >= 3:
                    st.warning("Too many failed attempts. Redirecting to Login page.")
                    st.experimental_rerun()
        else:
            st.error("Both fields are required.")


# login
with tab4:
    st.subheader("Reauthorization Required")
    st.write("You've reached the login wall after 3 failed attempts.")
    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if hash_passkey(login_pass) == MASTER_HASHED:
            failed_attempts = 0
            st.success("Reauthorized successfully! Redirecting...")
            st.experimental_rerun()
        else:
            st.error("Incorrect password.")