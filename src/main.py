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
        print("\n--- REGISTER ---")
        username = input("Username: ")
        password = getpass.getpass("Password: ")
        
        # Генерируем ключи шифрования при регистрации
        self.messenger.generate_keys()
        self.messenger.save_keys(username, KEYS_DIR)
        pub_key = self.messenger.get_public_key_pem()

        # ИСПРАВЛЕНО: передаем pub_key (а не public_key)
        success, result = self.auth.register_user(username, password, pub_key)
        
        if success:
            print(f"\n[OK] User created! Keys saved to keys/{username}.pem")
            qr = qrcode.QRCode()
            qr.add_data(result)
            f = io.StringIO()
            qr.print_ascii(out=f)
            f.seek(0)
            print(f.read())
            print(f"Secret: {result.split('secret=')[1].split('&')[0]}")
            self.ledger.mine_block()
        else:
            print(f"\n[ERROR] {result}")

    def login_flow(self):
        print("\n--- LOGIN ---")
        username = input("Username: ")
        password = getpass.getpass("Password: ")
        totp = input("2FA Code: ")

        success, result = self.auth.login(username, password, totp)

        if success:
            self.current_user = username
            # Загружаем ключи пользователя
            if self.messenger.load_keys(username, KEYS_DIR):
                print(f"\n[SUCCESS] Welcome {username}! Encryption keys loaded.")
            else:
                print(f"\n[WARNING] Welcome {username}, but KEYS NOT FOUND. Messaging unavailable.")
            self.ledger.mine_block()
        else:
            print(f"\n[DENIED] {result}")

    def send_message_flow(self):
        print("\n--- SEND MESSAGE ---")
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
        print(f"\n--- INBOX ({self.current_user}) ---")
        all_msgs = self.load_inbox()
        my_msgs = [m for m in all_msgs if m.get('to') == self.current_user]

        if not my_msgs:
            print("No messages.")
            return

        for i, msg in enumerate(my_msgs):
            print(f"\n[{i+1}] From: {msg['from']}")
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
            
            choice = input("\nSelect: ")

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
            
            input("\nPress Enter...")

if __name__ == "__main__":
    app = CryptoVaultCLI()
    app.main_menu()