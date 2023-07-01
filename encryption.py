import itertools
import hashlib
import secrets


def rsa_keygen(bits: int) -> tuple[int, int]:
    p = _generate_prime(bits // 2)
    q = _generate_prime(bits // 2)
    mod = p * q
    m = (p - 1) * (q - 1)
    public_key = 65537
    private_key = pow(public_key, -1, m)
    return private_key, mod


def _generate_prime(bits: int) -> int:
    while True:
        prime = secrets.randbits(bits)
        if _is_prime(prime):
            return prime

# no idea what this does, its just a copy of https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test#Example
def _is_prime(n: int) -> bool:
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    s = 0
    d = n - 1
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(40):
        a = secrets.randbelow(n-4) + 2
        x = pow(a, d, n)
        for _ in range(s):
            y = pow(x, 2, n)
            if y == 1 and x != 1 and x != n-1:
                return False
            x = y
        if x != 1:
            return False

    return True


def rsa_encrypt(message: int, key: int, modulus: int) -> int:
    return pow(message, key, modulus)


# basic cipher
class Encryption:
    def __init__(self, key: bytes = b"", rounds = 512):
        if not key:
            key = secrets.token_bytes(255)
        self.key = key
        self.rounds = rounds

    def _hash(self, data: bytes) -> bytes:
        """
        fuck ton of hashing
        """
        rounds = 256

        for _ in range(rounds):
            data = hashlib.sha512(data).digest()

        return data

    def _xor(self, data: bytes, key: bytes) -> bytes:
        return bytes(a ^ b for a, b in zip(data, key))
    
    def encrypt(self, data: bytes):
        key = itertools.cycle(self.key)
        temp = int.from_bytes(data, "little") ^ int.from_bytes(self.key, "little")
        data = temp.to_bytes((temp.bit_length() + 7) // 8, "little")
        for round in range(self.rounds):
            curkey = next(key) + round
            curkey = curkey.to_bytes((curkey.bit_length() + 7) // 8, "little")
            curkey = self._hash(curkey)
            data = self._xor(data, curkey)
        
        return data

    def round(self, data, subkey):
        return self._xor(data, subkey)

