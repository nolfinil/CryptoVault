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