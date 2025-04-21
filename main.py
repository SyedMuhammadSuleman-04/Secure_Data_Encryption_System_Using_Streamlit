# import streamlit as st
# import json
# import os
# import time
# import base64
# from hashlib import pbkdf2_hmac
# from cryptography.fernet import Fernet

# # ------------------ File Paths ------------------ #
# DATA_FILE = "stored_data.json"

# # ------------------ Global Variables ------------------ #
# stored_data = {}
# failed_attempts = 0
# lockout_time = None
# SALT = b"streamlit_salt"  # Use a strong unique salt in production

# # ------------------ Encryption Setup ------------------ #
# KEY = Fernet.generate_key()
# cipher = Fernet(KEY)

# # ------------------ Load and Save ------------------ #
# def load_data():
#     global stored_data
#     if os.path.exists(DATA_FILE):
#         with open(DATA_FILE, "r") as f:
#             stored_data = json.load(f)
#     else:
#         stored_data = {}

# def save_data():
#     with open(DATA_FILE, "w") as f:
#         json.dump(stored_data, f)

# # ------------------ Hashing Function ------------------ #
# def hash_passkey(passkey):
#     key = pbkdf2_hmac("sha256", passkey.encode(), SALT, 100000)
#     return base64.b64encode(key).decode()

# # ------------------ Encryption & Decryption ------------------ #
# def encrypt_data(text):
#     return cipher.encrypt(text.encode()).decode()

# def decrypt_data(encrypted_text, passkey):
#     global failed_attempts, lockout_time
#     if is_locked():
#         return "LOCKED"

#     hashed_passkey = hash_passkey(passkey)
#     for user, values in stored_data.items():
#         if values["encrypted_text"] == encrypted_text and values["passkey"] == hashed_passkey:
#             failed_attempts = 0
#             return cipher.decrypt(encrypted_text.encode()).decode()

#     failed_attempts += 1
#     if failed_attempts >= 3:
#         lockout_time = time.time()
#     return None

# # ------------------ Lockout Timer ------------------ #
# def is_locked():
#     if lockout_time and (time.time() - lockout_time < 30):
#         return True
#     return False

# # ------------------ Users ------------------ #
# users = {
#     "admin": hash_passkey("admin123"),
#     "suleman": hash_passkey("mysecurepass")
# }

# # ------------------ Load stored data on startup ------------------ #
# load_data()

# # ------------------ Streamlit UI ------------------ #
# st.set_page_config(page_title="Secure Data App", page_icon="🔐")
# st.title("🔐 Secure Data Encryption System")

# if "current_user" not in st.session_state:
#     st.session_state.current_user = None

# # ------------------ Login Page ------------------ #
# if not st.session_state.current_user:
#     st.subheader("🔑 User Login")
#     username = st.text_input("Username")
#     password = st.text_input("Password", type="password")

#     if st.button("Login"):
#         if username in users and users[username] == hash_passkey(password):
#             st.session_state.current_user = username
#             st.success(f"✅ Logged in as {username}")
#             st.rerun()  # Use `st.rerun()` instead of deprecated `st.experimental_rerun()`
#         else:
#             st.error("❌ Invalid username or password")

# else:
#     # ------------------ Sidebar Navigation ------------------ #
#     menu = ["Home", "Store Data", "Retrieve Data", "Logout"]
#     choice = st.sidebar.selectbox("Navigation", menu)

#     if choice == "Home":
#         st.subheader("🏠 Welcome to the Secure Data System")
#         st.write("Use this app to **securely store and retrieve data** using unique passkeys.")
#         st.success(f"Logged in as: {st.session_state.current_user}")

#     elif choice == "Store Data":
#         st.subheader("📂 Store Data Securely")
#         user_data = st.text_area("Enter Data:")
#         passkey = st.text_input("Enter Passkey:", type="password")

#         if st.button("Encrypt & Save"):
#             if user_data and passkey:
#                 hashed_passkey = hash_passkey(passkey)
#                 encrypted_text = encrypt_data(user_data)
#                 stored_data[st.session_state.current_user] = {
#                     "encrypted_text": encrypted_text,
#                     "passkey": hashed_passkey
#                 }
#                 save_data()
#                 st.success("✅ Data stored securely!")
#                 st.code(encrypted_text, language="text")
#             else:
#                 st.error("⚠️ Both fields are required!")

#     elif choice == "Retrieve Data":
#         st.subheader("🔍 Retrieve Your Data")
#         encrypted_text = st.text_area("Enter Encrypted Data:")
#         passkey = st.text_input("Enter Passkey:", type="password")

#         if st.button("Decrypt"):
#             if is_locked():
#                 st.warning("⏳ Too many attempts! Locked for 30 seconds.")
#             elif encrypted_text and passkey:
#                 result = decrypt_data(encrypted_text, passkey)
#                 if result == "LOCKED":
#                     st.warning("⏳ Locked out! Try again later.")
#                 elif result:
#                     st.success(f"✅ Decrypted Data: {result}")
#                 else:
#                     st.error(f"❌ Incorrect passkey! Attempts left: {3 - failed_attempts}")
#             else:
#                 st.error("⚠️ Both fields are required!")

#     elif choice == "Logout":
#         st.session_state.current_user = None
#         st.rerun()  # Use `st.rerun()` instead of deprecated `st.experimental_rerun()`

import streamlit as st
import sqlite3
import hashlib
import os
from cryptography.fernet import Fernet

KEY_FILE = "simple_secret_key"

def generate_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    else:
        with open(KEY_FILE, "rb") as f:
            key = f.read()
    return key

cipher = Fernet(generate_key())

def init_db():
    conn = sqlite3.connect("simple_data.db")
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            label TEXT PRIMARY KEY,
            encrypted_secret TEXT NOT NULL,
            passkey TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

# ✅ Call the DB initialization
init_db()

def hash_password(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

# Streamlit UI
st.title("🧠💾 Memory Vault: Where Secrets Sleep Securely")
st.subheader("Encrypt once. Retrieve when needed.")

menu = ["Store Secret", "Retrieve Secret"]
choice = st.sidebar.selectbox("Select an option", menu)

if choice == "Store Secret":
    st.subheader("Store your secret")

    label = st.text_input("Label (Unique ID): ")
    secret = st.text_area("Secret (Text): ")
    passkey = st.text_input("Passkey (Password): ", type="password")

    if st.button("Encrypt and Save"):
        if label and secret and passkey:
            conn = sqlite3.connect("simple_data.db")
            cursor = conn.cursor()

            encrypted_secret = encrypt(secret)
            hashed_passkey = hash_password(passkey)

            try:
                cursor.execute("INSERT INTO users (label, encrypted_secret, passkey) VALUES (?, ?, ?)",
                               (label, encrypted_secret, hashed_passkey))
                conn.commit()
                st.success("✅ Secret stored successfully!")
            except sqlite3.IntegrityError:
                st.error("❌ Label already exists. Please choose a different one.")
            finally:
                conn.close()
        else:
            st.warning("⚠️ Please fill all the fields.")

elif choice == "Retrieve Secret":
    st.subheader("Retrieve a stored secret")

    label = st.text_input("Enter label of the secret: ")
    passkey = st.text_input("Enter passkey: ", type="password")

    if st.button("Decrypt and Retrieve"):
        conn = sqlite3.connect("simple_data.db")
        cursor = conn.cursor()
        cursor.execute("SELECT encrypted_secret, passkey FROM users WHERE label = ?", (label,))
        result = cursor.fetchone()
        conn.close()

        if result:
            encrypted_secret, hashed_passkey = result
            if hash_password(passkey) == hashed_passkey:
                decrypted_secret = decrypt(encrypted_secret)
                st.success(f"🔓 Your secret: {decrypted_secret}")
            else:
                st.error("❌ Incorrect passkey.")
        else:
            st.error("❌ Label not found.")