#  CipherLock 
 
**Securely store and retrieve your secrets with just a passkey — no database, no leaks, just pure encryption magic.**

---

##  What It Does

- Encrypts any user-provided message using a secret passkey.  
- Stores encrypted data securely **in-memory** (nothing is written to disk).  
- Decrypts messages only when the **correct passkey** is provided.  
- After **3 incorrect attempts**, access is locked and the user is redirected to the Login page for reauthorization.  

---

##  Why It Works

- Uses **Fernet encryption** from the `cryptography` library for robust and reliable encryption.  
- **Passkeys are never stored directly** — instead, they’re hashed using **SHA-256**.  
- Built using **Streamlit** for a fast, friendly, and interactive web interface.  
- Entirely memory-based, means **no database** is needed. Ensuring simplicity and security for quick-use scenarios.  

---

##  Features:

-  Secure encryption & decryption using Fernet  
-  SHA-256 hashed passkeys  
-  Retry mechanism with limited attempts  
-  Auto lockout after 3 failed attempts  
-  User-friendly Streamlit UI  
-  Fully in-memory data storage  

---

## What's Good:

- Neat tab-based UI using Streamlit.
- Clear separation of functionality and UI.
- Encryption using Fernet is a solid choice.
- SHA-256 used for hashing passkeys (secure).
- Login wall after failed attempts — great for safety.
- This app stores data only in RAM.


---

## Project Structure:

| File/Folder            | Description                          |
|------------------------|--------------------------------------|
| `app.py`               | Main application code          |
| `README.md`            | Project documentation                |
| `requirements.txt`     | Python dependencies                  |

##  Wanna tweak?

To get CipherLock up and running:

- ✅ Clone or download this repository  
- ✅ Make sure Python 3.7+ is installed  
- ✅ Install required dependencies using pip  
- ✅ Open your terminal or command prompt  
- ✅ Run the Streamlit app  
- ✅ App will launch in your browser automatically  

> You’ll be able to store encrypted messages and retrieve them only using the correct passkey.


##  Contribution Guidelines

- Pull requests are welcome!  
- For major changes, please open an issue first to discuss what you would like to change.


---

##  License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

##  Author

Made by **Aqsaa Qaazi**  
_Python + Streamlit Assignment Project_

---

## ⚠️ Disclaimer

This app is a **demo project**. Please **do not use it for storing sensitive or personal information** in production environments.

**The master password is hardcoded as _admin123_ for demonstration. This is not secure for production.**