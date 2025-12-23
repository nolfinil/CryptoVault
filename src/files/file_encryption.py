import os
import hashlib
import hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

class FileEncryptionModule:
    def __init__(self, blockchain_logger=None):
        self.blockchain_logger = blockchain_logger

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return kdf.derive(password.encode())

    def encrypt_file(self, filepath: str, password: str) -> str:
        if not os.path.exists(filepath):
            raise FileNotFoundError("File not found")

        salt = os.urandom(16)
        key = self._derive_key(password, salt)
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)

        with open(filepath, 'rb') as f:
            data = f.read()

        file_hash = hashlib.sha256(data).hexdigest()
        
        ciphertext = aesgcm.encrypt(nonce, data, None)

        hmac_obj = hmac.new(key, ciphertext, hashlib.sha256)
        auth_tag = hmac_obj.digest()

        output_path = filepath + ".enc"
        with open(output_path, 'wb') as f:
            f.write(salt)
            f.write(nonce)
            f.write(auth_tag)
            f.write(ciphertext)

        if self.blockchain_logger:
            self.blockchain_logger.add_transaction(f"FILE_ENCRYPT: {os.path.basename(filepath)} SHA256:{file_hash}")

        return output_path

    def decrypt_file(self, enc_filepath: str, password: str) -> str:
        if not os.path.exists(enc_filepath):
            raise FileNotFoundError("File not found")

        with open(enc_filepath, 'rb') as f:
            salt = f.read(16)
            nonce = f.read(12)
            stored_tag = f.read(32)
            ciphertext = f.read()

        key = self._derive_key(password, salt)

        hmac_obj = hmac.new(key, ciphertext, hashlib.sha256)
        try:
            if not hmac.compare_digest(hmac_obj.digest(), stored_tag):
                raise ValueError("Integrity check failed (HMAC mismatch)")
        except Exception:
             raise ValueError("Integrity check failed")

        aesgcm = AESGCM(key)
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        except Exception:
            raise ValueError("Decryption failed (Invalid password or corrupted data)")

        output_path = enc_filepath.replace(".enc", ".dec")
        with open(output_path, 'wb') as f:
            f.write(plaintext)

        if self.blockchain_logger:
            self.blockchain_logger.add_transaction(f"FILE_DECRYPT: {os.path.basename(enc_filepath)}")

        return output_path