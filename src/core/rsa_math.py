__all__ = ["RSAMath"]

class RSAMath:
    @staticmethod
    def mod_exp(base: int, exponent: int, modulus: int) -> int:
        result = 1
        base = base % modulus
        while exponent > 0:
            if exponent % 2 == 1:
                result = (result * base) % modulus
            exponent = exponent // 2
            base = (base * base) % modulus
        return result

class RSAMath:
    @staticmethod
    def mod_exp(base: int, exponent: int, modulus: int) -> int:
        result = 1
        base = base % modulus
        while exponent > 0:
            if exponent % 2 == 1:
                result = (result * base) % modulus
            exponent = exponent // 2
            base = (base * base) % modulus
        return result