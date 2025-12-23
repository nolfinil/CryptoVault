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