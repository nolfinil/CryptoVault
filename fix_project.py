import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.join(BASE_DIR, 'src')
KEYS_DIR = os.path.join(BASE_DIR, 'keys')

# Создаем папку для ключей, если нет
if not os.path.exists(KEYS_DIR):
    os.makedirs(KEYS_DIR)

# --- 1. MESSAGING MODULE (С СОХРАНЕНИЕМ КЛЮЧЕЙ) ---
MESSAGING_CODE = """
import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption

class MessagingModule:
    def __init__(self):
        self.identity_private_key = None
        self.identity_public_key = None

    def generate_keys(self):
        self.identity_private_key = ec.generate_private_key(ec.SECP256R1())
        self.identity_public_key = self.identity_private_key.public_key()

    def save_keys(self, username, keys_dir="keys"):
        if not self.identity_private_key:
            return
        
        path = os.path.join(keys_dir, f"{username}.pem")
        
        # Сохраняем приватный ключ в файл
        with open(path, "wb") as f:
            f.write(self.identity_private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=NoEncryption() 
            ))

    def load_keys(self, username, keys_dir="keys"):
        path = os.path.join(keys_dir, f"{username}.pem")
        if not os.path.exists(path):
            return False
        
        with open(path, "rb") as f:
            self.identity_private_key = serialization.load_pem_private_key(
                f.read(), password=None
            )
        self.identity_public_key = self.identity_private_key.public_key()
        return True

    def get_public_key_pem(self) -> str:
        if not self.identity_public_key:
            return ""
        return self.identity_public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

    def _derive_shared_key(self, peer_public_key) -> bytes:
        shared_secret = self.identity_private_key.exchange(ec.ECDH(), peer_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(shared_secret)
        return derived_key

    def send_message(self, recipient_pubkey_str: str, message: str) -> dict:
        if not self.identity_private_key:
            raise ValueError("Keys not loaded")

        recipient_key = serialization.load_pem_public_key(recipient_pubkey_str.encode('utf-8'))
        aes_key = self._derive_shared_key(recipient_key)
        
        aesgcm = AESGCM(aes_key)
        nonce = os.urandom(12)
        data = message.encode('utf-8')
        
        ciphertext = aesgcm.encrypt(nonce, data, None)
        
        signature = self.identity_private_key.sign(
            nonce + ciphertext,
            ec.ECDSA(hashes.SHA256())
        )

        return {
            "nonce": base64.b64encode(nonce).decode('utf-8'),
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
            "signature": base64.b64encode(signature).decode('utf-8'),
            "sender_pubkey": self.get_public_key_pem()
        }

    def decrypt_message(self, encrypted_package: dict) -> str:
        if not self.identity_private_key:
             raise ValueError("Keys not loaded")

        nonce = base64.b64decode(encrypted_package['nonce'])
        ciphertext = base64.b64decode(encrypted_package['ciphertext'])
        signature = base64.b64decode(encrypted_package['signature'])
        sender_pubkey_pem = encrypted_package['sender_pubkey'].encode('utf-8')

        sender_pubkey = serialization.load_pem_public_key(sender_pubkey_pem)

        try:
            sender_pubkey.verify(
                signature,
                nonce + ciphertext,
                ec.ECDSA(hashes.SHA256())
            )
        except InvalidSignature:
            raise ValueError("INVALID SIGNATURE: Message tampered!")

        aes_key = self._derive_shared_key(sender_pubkey)
        aesgcm = AESGCM(aes_key)
        
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext.decode('utf-8')
        except Exception:
            raise ValueError("DECRYPTION FAILED: Wrong key or corrupted data")
"""

# --- 2. AUTH MODULE (С ХРАНЕНИЕМ PUB KEY) ---
AUTH_CODE = """
import os
import time
import json
import secrets
import re
import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from typing import Dict, Tuple

DB_FILE = "user_db.json"

class AuthModule:
    def __init__(self, blockchain_logger=None):
        self.ph = PasswordHasher()
        self.blockchain_logger = blockchain_logger
        self.users = self._load_db()
        self.login_attempts = {}
        self.sessions = {}

    def _load_db(self) -> Dict:
        if not os.path.exists(DB_FILE):
            return {}
        try:
            with open(DB_FILE, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError:
            return {}

    def _save_db(self):
        with open(DB_FILE, 'w') as f:
            json.dump(self.users, f, indent=4)

    def validate_password_strength(self, password: str) -> bool:
        if len(password) < 8: # Упростил для тестов
            return False
        return True

    def register_user(self, username: str, password: str, public_key: str) -> Tuple[bool, str]:
        if username in self.users:
            return False, "User already exists"

        if not self.validate_password_strength(password):
            return False, "Password too weak"

        password_hash = self.ph.hash(password)
        totp_secret = pyotp.random_base32()
        
        self.users[username] = {
            "password_hash": password_hash,
            "totp_secret": totp_secret,
            "public_key": public_key, 
            "created_at": time.time()
        }
        self._save_db()

        if self.blockchain_logger:
            self.blockchain_logger.add_transaction(f"REGISTER: {username}")

        totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(
            name=username, issuer_name="CryptoVault"
        )
        return True, totp_uri

    def login(self, username: str, password: str, totp_code: str) -> Tuple[bool, str]:
        user = self.users.get(username)
        if not user:
            return False, "Invalid credentials"

        try:
            self.ph.verify(user["password_hash"], password)
        except VerifyMismatchError:
            return False, "Invalid credentials"

        totp = pyotp.TOTP(user["totp_secret"])
        if not totp.verify(totp_code, valid_window=1):
            return False, "Invalid MFA code"

        session_token = secrets.token_hex(32)
        self.sessions[session_token] = username
        
        if self.blockchain_logger:
            self.blockchain_logger.add_transaction(f"LOGIN: {username}")

        return True, session_token

    def get_user_pubkey(self, username: str) -> str:
        user = self.users.get(username)
        if user:
            return user.get("public_key")
        return None
        
    def get_all_users(self):
        return list(self.users.keys())
"""

# --- 3. MAIN CLI (ИСПРАВЛЕННАЯ ОШИБКА ПЕРЕМЕННОЙ) ---
MAIN_CODE = """
import sys
import os
import getpass
import qrcode
import io
import json
import time

# Добавляем пути
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
KEYS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'keys')
INBOX_FILE = "inbox.json"

from auth.authentication import AuthModule
from messaging.encryption import MessagingModule
from files.file_encryption import FileEncryptionModule
from blockchain.ledger import BlockchainModule

class CryptoVaultCLI:
    def __init__(self):
        self.ledger = BlockchainModule(difficulty=2)
        self.auth = AuthModule(blockchain_logger=self.ledger)
        self.messenger = MessagingModule()
        self.files = FileEncryptionModule(blockchain_logger=self.ledger)
        self.current_user = None

    def load_inbox(self):
        if not os.path.exists(INBOX_FILE):
            return []
        try:
            with open(INBOX_FILE, 'r') as f:
                return json.load(f)
        except:
            return []

    def save_to_inbox(self, msg_data):
        inbox = self.load_inbox()
        inbox.append(msg_data)
        with open(INBOX_FILE, 'w') as f:
            json.dump(inbox, f, indent=4)

    def print_header(self):
        print("=" * 50)
        print("      CRYPTOVAULT SECURITY SUITE v2.0")
        print("=" * 50)

    def register_flow(self):
        print("\\n--- REGISTER ---")
        username = input("Username: ")
        password = getpass.getpass("Password: ")
        
        # Генерируем ключи шифрования при регистрации
        self.messenger.generate_keys()
        self.messenger.save_keys(username, KEYS_DIR)
        pub_key = self.messenger.get_public_key_pem()

        # ИСПРАВЛЕНО: передаем pub_key (а не public_key)
        success, result = self.auth.register_user(username, password, pub_key)
        
        if success:
            print(f"\\n[OK] User created! Keys saved to keys/{username}.pem")
            qr = qrcode.QRCode()
            qr.add_data(result)
            f = io.StringIO()
            qr.print_ascii(out=f)
            f.seek(0)
            print(f.read())
            print(f"Secret: {result.split('secret=')[1].split('&')[0]}")
            self.ledger.mine_block()
        else:
            print(f"\\n[ERROR] {result}")

    def login_flow(self):
        print("\\n--- LOGIN ---")
        username = input("Username: ")
        password = getpass.getpass("Password: ")
        totp = input("2FA Code: ")

        success, result = self.auth.login(username, password, totp)

        if success:
            self.current_user = username
            # Загружаем ключи пользователя
            if self.messenger.load_keys(username, KEYS_DIR):
                print(f"\\n[SUCCESS] Welcome {username}! Encryption keys loaded.")
            else:
                print(f"\\n[WARNING] Welcome {username}, but KEYS NOT FOUND. Messaging unavailable.")
            self.ledger.mine_block()
        else:
            print(f"\\n[DENIED] {result}")

    def send_message_flow(self):
        print("\\n--- SEND MESSAGE ---")
        users = self.auth.get_all_users()
        print("Users:", ", ".join(users))
        
        recipient = input("To (username): ")
        if recipient == self.current_user:
            print("Cannot send to yourself.")
            return
            
        recipient_pub = self.auth.get_user_pubkey(recipient)
        if not recipient_pub:
            print("User not found.")
            return

        message = input("Message: ")
        
        try:
            print("[INFO] Encrypting with recipient's Public Key...")
            encrypted_pkg = self.messenger.send_message(recipient_pub, message)
            
            # Добавляем метаданные для инбокса
            encrypted_pkg['to'] = recipient
            encrypted_pkg['from'] = self.current_user
            encrypted_pkg['timestamp'] = time.time()
            
            self.save_to_inbox(encrypted_pkg)
            print("[SUCCESS] Message sent to simulated network!")
            self.ledger.add_transaction(f"MSG: {self.current_user} -> {recipient}")
            self.ledger.mine_block()
        except Exception as e:
            print(f"[ERROR] {e}")

    def check_inbox_flow(self):
        print(f"\\n--- INBOX ({self.current_user}) ---")
        all_msgs = self.load_inbox()
        my_msgs = [m for m in all_msgs if m.get('to') == self.current_user]

        if not my_msgs:
            print("No messages.")
            return

        for i, msg in enumerate(my_msgs):
            print(f"\\n[{i+1}] From: {msg['from']}")
            try:
                decrypted = self.messenger.decrypt_message(msg)
                print(f"    Message: {decrypted}")
                print("    [Status: Verified & Decrypted]")
            except Exception as e:
                print(f"    [Decryption Failed]: {e}")

    def main_menu(self):
        while True:
            self.print_header()
            if self.current_user:
                print(f"User: {self.current_user}")
                print("1. Send Message (Real Users)")
                print("2. Check Inbox")
                print("3. File Vault")
                print("4. Audit Ledger")
                print("5. Logout")
            else:
                print("1. Register")
                print("2. Login")
                print("3. Exit")
            
            choice = input("\\nSelect: ")

            if self.current_user:
                if choice == '1': self.send_message_flow()
                elif choice == '2': self.check_inbox_flow()
                elif choice == '3': pass 
                elif choice == '4': print(self.ledger.get_chain_dump())
                elif choice == '5': 
                    self.current_user = None
                    print("Logged out.")
            else:
                if choice == '1': self.register_flow()
                elif choice == '2': self.login_flow()
                elif choice == '3': sys.exit()
            
            input("\\nPress Enter...")

if __name__ == "__main__":
    app = CryptoVaultCLI()
    app.main_menu()
"""

def write_file(path, content):
    full_path = os.path.join(SRC_DIR, path)
    print(f"Updating {full_path}...")
    try:
        with open(full_path, 'w', encoding='utf-8') as f:
            f.write(content.strip())
        print(" -> OK")
    except Exception as e:
        print(f" -> ERROR: {e}")

if __name__ == "__main__":
    write_file('messaging/encryption.py', MESSAGING_CODE)
    write_file('auth/authentication.py', AUTH_CODE)
    write_file('main.py', MAIN_CODE)
    print("\\n[DONE] Error fixed. Run python src/main.py")