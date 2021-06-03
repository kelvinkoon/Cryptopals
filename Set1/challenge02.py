# https://cryptopals.com/sets/1/challenges/2


def decodeFixedXOR(input_bytes: bytes, key_bytes: bytes) -> bytes:
    """
    Operates a fixed XOR between two byte arrays
    Returns a fixed XOR byte array

    :param input_bytes Byte array to decode
    :param key_bytes Byte array acting as key
    """
    if len(input_bytes) != len(key_bytes):
        raise Exception("Input string and key are not equal lengths")

    # Store individual byte XOR results
    xor_bytes = b""
    for i in range(0, len(input_bytes)):
        xor_bytes += bytes([input_bytes[i] ^ key_bytes[i]])

    return xor_bytes
