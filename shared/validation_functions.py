# File for commonly used functions between Challenge Sets
from Crypto.Hash import SHA1

# Testing utilities
def hashBytesToSHA1Str(input_bytes: bytes) -> str:
    """
    Returns the SHA1 hex string given a byte array

    :param input_bytes The byte array to hash
    """
    h = SHA1.new()
    h.update(input_bytes)
    return h.hexdigest()
