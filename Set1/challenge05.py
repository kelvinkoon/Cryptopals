# https://cryptopals.com/sets/1/challenges/5


def encodeRepeatingKeyXOR(input_bytes: bytes, key_bytes: bytes) -> bytes:
    """
    Encodes a byte array with a repeating key byte array
    Returns a byte array encoded using a vigenere cipher

    :param input_bytes The byte array to be encoded
    :param key_bytes The byte array acting as key
    """
    xor_bytes = b""
    for i in range(0, len(input_bytes)):
        # XOR with repeating key
        xor_bytes += bytes([input_bytes[i] ^ key_bytes[i % len(key_bytes)]])

    return xor_bytes
