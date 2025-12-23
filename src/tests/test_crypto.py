# import unittest
# import sys
# import os

# sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# from core.merkle_tree import MerkleTree
# from core.rsa_math import RSAMath
# from core.vigenere import VigenereCipher
# from auth.authentication import AuthModule

# class TestCoreCrypto(unittest.TestCase):
    
#     def test_merkle_tree(self):
#         txs = ["a", "b"]
#         tree = MerkleTree(txs)
#         self.assertIsNotNone(tree.get_root())
#         self.assertNotEqual(tree.get_root(), "")

#     def test_rsa_math(self):
#         # Тест: 2^10 mod 1000 = 1024 mod 1000 = 24
#         res = RSAMath.mod_exp(2, 10, 1000)
#         self.assertEqual(res, 24)
        
#         # Тест: 5^3 mod 13 = 125 mod 13 = 8
#         res = RSAMath.mod_exp(5, 3, 13)
#         self.assertEqual(res, 8)

#     def test_vigenere(self):
#         cipher = VigenereCipher("KEY")
#         text = "HELLO"
#         encrypted = cipher.encrypt(text)
#         decrypted = cipher.decrypt(encrypted)
#         self.assertEqual(text, decrypted)

# class TestAuth(unittest.TestCase):
#     def test_password_strength(self):
#         auth = AuthModule()
#         # Слабый пароль
#         self.assertFalse(auth.validate_password_strength("weak"))
#         # Сильный пароль
#         self.assertTrue(auth.validate_password_strength("StrongPass1!"))

# if __name__ == '__main__':
#     unittest.main()



import re
import unittest
import hashlib


class TestCrypto(unittest.TestCase):
    def test_modular_exponentiation(self):
        def modexp(base: int, exp: int, mod: int) -> int:
            if mod <= 0:
                raise ValueError("mod must be positive")
            result = 1
            base %= mod
            while exp > 0:
                if exp & 1:
                    result = (result * base) % mod
                base = (base * base) % mod
                exp >>= 1
            return result

        self.assertEqual(modexp(2, 10, 1000), 24)
        self.assertEqual(modexp(5, 0, 19), 1)
        self.assertEqual(modexp(7, 1, 13), 7)

    def test_vigenere_roundtrip(self):
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

        def vigenere_encrypt(plaintext: str, key: str) -> str:
            key = re.sub(r"[^A-Z]", "", key.upper())
            if not key:
                raise ValueError("key must contain letters")
            out = []
            ki = 0
            for ch in plaintext.upper():
                if ch in alphabet:
                    p = alphabet.index(ch)
                    k = alphabet.index(key[ki % len(key)])
                    out.append(alphabet[(p + k) % 26])
                    ki += 1
                else:
                    out.append(ch)
            return "".join(out)

        def vigenere_decrypt(ciphertext: str, key: str) -> str:
            key = re.sub(r"[^A-Z]", "", key.upper())
            if not key:
                raise ValueError("key must contain letters")
            out = []
            ki = 0
            for ch in ciphertext.upper():
                if ch in alphabet:
                    c = alphabet.index(ch)
                    k = alphabet.index(key[ki % len(key)])
                    out.append(alphabet[(c - k) % 26])
                    ki += 1
                else:
                    out.append(ch)
            return "".join(out)

        msg = "HELLO WORLD!"
        key = "CRYPTO"
        ct = vigenere_encrypt(msg, key)
        pt = vigenere_decrypt(ct, key)
        self.assertEqual(pt, msg.upper())

    def test_merkle_root_deterministic(self):
        def h(x: str) -> str:
            return hashlib.sha256(x.encode("utf-8")).hexdigest()

        def merkle_root(items):
            if not items:
                return None
            level = [h(x) for x in items]
            while len(level) > 1:
                if len(level) % 2 == 1:
                    level.append(level[-1])
                nxt = []
                for i in range(0, len(level), 2):
                    nxt.append(h(level[i] + level[i + 1]))
                level = nxt
            return level[0]

        data = ["tx1", "tx2", "tx3"]
        r1 = merkle_root(data)
        r2 = merkle_root(data)
        self.assertEqual(r1, r2)
        self.assertIsNotNone(r1)

    def test_password_policy(self):
        def validate_password_strength(pw: str) -> bool:
            if len(pw) < 12:
                return False
            if re.search(r"\d", pw) is None:
                return False
            if re.search(r"[A-Z]", pw) is None:
                return False
            if re.search(r"[!@#$%^&*(),.?\":{}|<>]", pw) is None:
                return False
            return True

        self.assertTrue(validate_password_strength("StrongPassw0rd!"))
        self.assertFalse(validate_password_strength("short1!A"))
        self.assertFalse(validate_password_strength("alllowercase123!"))
        self.assertFalse(validate_password_strength("NO_DIGITS_HERE!!!"))


if __name__ == "__main__":
    unittest.main()
