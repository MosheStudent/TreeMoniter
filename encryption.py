import os

class Encryption:
    def __init__(self, key):
        self.key = key.encode() if isinstance(key, str) else key

    def encrypt(self, data):
        if isinstance(data, str):
            data = data.encode()
        key_bytes = self._extend_key(len(data))
        return bytes(a ^ b for a, b in zip(data, key_bytes))

    def decrypt(self, data):
        return self.encrypt(data)  # XOR is its own inverse

    def _extend_key(self, length):
        return (self.key * (length // len(self.key) + 1))[:length]