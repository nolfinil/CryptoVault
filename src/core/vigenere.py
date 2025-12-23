class VigenereCipher:
    """
    Реализация шифра Виженера (Option A).
    Классический полиалфавитный шифр.
    """
    def __init__(self, key: str):
        self.key = key.upper()

    def encrypt(self, plaintext: str) -> str:
        encrypted = []
        key_index = 0
        for char in plaintext:
            if char.isalpha():
                shift = ord(self.key[key_index % len(self.key)]) - ord('A')
                if char.isupper():
                    encrypted_char = chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
                else:
                    encrypted_char = chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
                encrypted.append(encrypted_char)
                key_index += 1
            else:
                encrypted.append(char)
        return "".join(encrypted)

    def decrypt(self, ciphertext: str) -> str:
        decrypted = []
        key_index = 0
        for char in ciphertext:
            if char.isalpha():
                shift = ord(self.key[key_index % len(self.key)]) - ord('A')
                if char.isupper():
                    decrypted_char = chr((ord(char) - ord('A') - shift + 26) % 26 + ord('A'))
                else:
                    decrypted_char = chr((ord(char) - ord('a') - shift + 26) % 26 + ord('a'))
                decrypted.append(decrypted_char)
                key_index += 1
            else:
                decrypted.append(char)
        return "".join(decrypted)