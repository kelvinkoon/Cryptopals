# https://cryptopals.com/sets/1/challenges/3
import binascii

INPUT_STR = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
EXPECTED_DECODED_ASCII_BYTES = b"Cooking MC's like a pound of bacon"
EXPECTED_KEY_BYTES = b"X"

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


def decodeSingleByteXORKey(ascii_bytes, key_byte):
    """
    XORs an ASCII byte array against a key byte
    Returns an byte array

    :param ascii_byte A byte array of ASCII characters
    :param key_byte A byte representing a key
    """
    xor_bytes = b""
    for i in range(0, len(ascii_bytes)):
        xor_bytes += bytes([ascii_bytes[i] ^ key_byte])

    return xor_bytes


def scoreASCIIByteArray(ascii_bytes):
    """
    Returns an integer score based on likelihood ASCII bytes represent an English sentence

    :param ascii_byte A byte array of ASCII characters
    """
    score = 0
    for ascii_byte in ascii_bytes:
        # Score according to character frequency dictionary
        # Ignore values outside of dictionary
        score += CHAR_FREQ_VAL.get(chr(ascii_byte).lower(), 0)

    return score


def decodeSingleByteXORCipher(hex_enc_str):
    """
    Brute-forces XOR operations through 256 ASCII keys against a hex-encoded string
    Returns the likeliest decoded ASCII byte array, "score", and likeliest key byte

    :param hex_enc_str A hex-encoded string
    """
    # Decode inputs from hex
    input_ascii_bytes = binascii.unhexlify(hex_enc_str.encode())

    # Initialize most likely string, score, and key byte
    probable_ascii_bytes = b""
    probable_score = 0
    probable_key_byte = b""

    # Attempt 256 ASCII keys
    for key_byte in range(0, 256):
        decoded_xor_bytes = decodeSingleByteXORKey(input_ascii_bytes, key_byte)
        decoded_xor_score = scoreASCIIByteArray(decoded_xor_bytes)

        if decoded_xor_score > probable_score:
            probable_ascii_bytes = decoded_xor_bytes
            probable_score = decoded_xor_score
            probable_key_byte = bytes([key_byte])

    return probable_ascii_bytes, probable_score, probable_key_byte


def main():
    output_ascii_bytes, _, output_key_byte = decodeSingleByteXORCipher(INPUT_STR)
    assert output_ascii_bytes.decode("utf-8") == EXPECTED_DECODED_ASCII_BYTES.decode(
        "utf-8"
    )
    assert output_key_byte.decode("utf-8") == EXPECTED_KEY_BYTES.decode("utf-8")


if __name__ == "__main__":
    main()
