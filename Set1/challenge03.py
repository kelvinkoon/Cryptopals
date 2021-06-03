# https://cryptopals.com/sets/1/challenges/3
from typing import Union

# Taken from https://crypto.stackexchange.com/a/40930
# Assigning space a value greatly improves decoding
CHAR_FREQ_VAL = {
    "a": 0.0651738,
    "b": 0.0124248,
    "c": 0.0217339,
    "d": 0.0349835,
    "e": 0.1041442,
    "f": 0.0197881,
    "g": 0.0158610,
    "h": 0.0492888,
    "i": 0.0558094,
    "j": 0.0009033,
    "k": 0.0050529,
    "l": 0.0331490,
    "m": 0.0202124,
    "n": 0.0564513,
    "o": 0.0596302,
    "p": 0.0137645,
    "q": 0.0008606,
    "r": 0.0497563,
    "s": 0.0515760,
    "t": 0.0729357,
    "u": 0.0225134,
    "v": 0.0082903,
    "w": 0.0171272,
    "x": 0.0013692,
    "y": 0.0145984,
    "z": 0.0007836,
    " ": 0.1918182,
}


def decodeSingleByteXORKey(input_bytes: bytes, key_byte: bytes) -> bytes:
    """
    XORs a byte array against a key byte
    Returns an byte array

    :param input_bytes A byte array to decode
    :param key_byte A byte representing a key
    """
    xor_bytes = b""
    for i in range(0, len(input_bytes)):
        xor_bytes += bytes([input_bytes[i] ^ key_byte])

    return xor_bytes


def scoreByteArray(input_bytes: bytes) -> int:
    """
    Returns an integer score based on likelihood ASCII bytes represent an English sentence

    :param input_bytes A byte array to be scored
    """
    score = 0
    for input_byte in input_bytes:
        # Score according to character frequency dictionary
        # Ignore values outside of dictionary
        score += CHAR_FREQ_VAL.get(chr(input_byte).lower(), 0)

    return score


def decodeSingleByteXORCipher(input_bytes: bytes) -> Union[bytes, int, bytes]:
    """
    Brute-forces XOR operations through 256 ASCII keys against the input byte array
    Returns the likeliest decoded byte array, "score", and likeliest key byte

    :param input_bytes The input byte array to be decoded
    """
    # Initialize most likely string, score, and key byte
    probable_ascii_bytes = b""
    probable_score = 0
    probable_key_byte = b""

    # Attempt 256 ASCII keys
    for key_byte in range(0, 256):
        decoded_xor_bytes = decodeSingleByteXORKey(input_bytes, key_byte)
        decoded_xor_score = scoreByteArray(decoded_xor_bytes)

        if decoded_xor_score > probable_score:
            probable_ascii_bytes = decoded_xor_bytes
            probable_score = decoded_xor_score
            probable_key_byte = bytes([key_byte])

    return probable_ascii_bytes, probable_score, probable_key_byte
