import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import os
import json

# Global variable declaration
# Global declaration (required by your teacher)
global failed_attempts
failed_attempts = st.session_state.get("failed_attempts", 0)

# In-memory data storage
stored_data = "data.json"

def load_key():
    key_file = "secret.key"
    if os.path.exists(key_file):
        key = open(key_file, "rb").read()
        if key:  # file is not empty
            return key
    # generate a new key if file doesn't exist or is empty
    key = Fernet.generate_key()
    with open(key_file, "wb") as f:
        f.write(key)
    return key

KEY = load_key()
cipher = Fernet(KEY)

def load_data():
    if os.path.exists(stored_data):
        with open(stored_data, "r") as file:
            return json.load(file)
    else:
        return []
        
def save_data(data):
    with open(stored_data, "w") as file:
        json.dump(data, file, indent=4)

# Function to hash passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Function to encrypt data
def encrypt_data(text, passkey):
    return cipher.encrypt(text.encode()).decode()

# Function to decrypt data
def decrypt_data(encrypted_text, passkey):
    global failed_attempts
    hashed_passkey = hash_passkey(passkey)
    loaded = load_data()
    for user in loaded:
        for key, value in user.items():
            if value["encrypted_text"] == encrypted_text and value["passkey"] == hashed_passkey:
                st.session_state.failed_attempts = 0
                return cipher.decrypt(encrypted_text.encode()).decode()
    
    st.session_state.failed_attempts += 1
    return None

master_password = "240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9"
def check_password(password):
    return hashlib.sha256(password.encode()).hexdigest() == master_password

if "authenticated" not in st.session_state:
    st.session_state.authenticated = False

if not st.session_state.authenticated:
    st.subheader("🔐 Login")
    login_pass = st.text_input("Enter Master Password:", type="password")
    if st.button("Login"):
        if check_password(login_pass):
            failed_attempts = 0
            st.session_state.failed_attempts = failed_attempts  # reset in session
            st.session_state.authenticated = True
            st.success("Logged in successfully!")
            st.rerun()
        else:
            failed_attempts += 1
            st.session_state.failed_attempts = failed_attempts
            st.warning(f"Remain Attempts {3 - failed_attempts}")
            st.error("Incorrect password")
            if failed_attempts >= 3:
                st.warning("🚫 Too many failed attempts. Please reload page.")
                if failed_attempts >3:
                    st.rerun()
else:
    st.title("🔒 Secure Data Encryption System")

    # Navigation
    menu = ["Home", "Store Data", "Retrieve Data", "Login"]
    choice = st.sidebar.selectbox("Navigation", menu)

    if choice == "Home":
        st.subheader("🏠 Welcome to the Secure Data System")
        st.write("Use this app to **securely store and retrieve data** using unique passkeys.")

    elif choice == "Store Data":
        st.subheader("📂 Store Data Securely")
        user_data = st.text_area("Enter Data:")
        passkey = st.text_input("Enter Passkey:", type="password")

        if st.button("Encrypt & Save"):
            if user_data and passkey:
                hashed_passkey = hash_passkey(passkey)
                encrypted_text = encrypt_data(user_data, passkey)
                data =  {
                user_data: {"encrypted_text": encrypted_text, "passkey": hashed_passkey},
                }
                loaded = load_data()
                loaded.append(data)
                save_data(loaded)
                st.success("✅ Data stored securely!")
            else:
                st.error("⚠️ Both fields are required!")

    elif choice == "Retrieve Data":
        st.subheader("🔍 Retrieve Your Data")
        loaded = load_data()
        encrypted_options = [list(entry.keys())[0] for entry in loaded]

        selected_data = st.selectbox("Select Encrypted Data:", encrypted_options)
        passkey = st.text_input("Enter Passkey:", type="password")

        if st.button("Decrypt"):
            st.session_state.failed_attempts = failed_attempts
            if selected_data and passkey:
                # Get stored encrypted value
                for item in loaded:
                    if selected_data in item:
                        encrypted_text = item[selected_data]["encrypted_text"]
                        break
                decrypted_text = decrypt_data(encrypted_text, passkey)
                if decrypted_text:
                    st.success(f"✅ Decrypted Data: {decrypted_text}")
                else:
                    failed_attempts += 1
                    st.session_state.failed_attempts = failed_attempts
                    st.error(f"❌ Incorrect passkey! Attempts remaining: {3 - failed_attempts}")

                    if failed_attempts >= 3:
                        st.warning("🔒 Too many failed attempts! Redirecting to Login Page.")
                        if failed_attempts >3:
                            st.rerun()
            else:
                st.error("⚠️ Both fields are required!")

    elif choice == "Login":
        st.subheader("🔑 Reauthorization Required")
        login_pass = st.text_input("Enter Master Password:", type="password")

        if st.button("Login"):
            login_success = check_password(login_pass)
            if login_success:
                st.success("✅ Reauthorized successfully! Redirecting to Retrieve Data...")
                st.rerun()
            else:
                failed_attempts += 1
                st.session_state.failed_attempts = failed_attempts
                st.error(f"❌ Incorrect passkey! Attempts remaining: {3 - failed_attempts}")
                st.error("❌ Incorrect password!")
                if failed_attempts >= 3:
                    st.warning("🔒 Too many failed attempts! Please reload the Page.")
                    if failed_attempts >3:
                        st.rerun()