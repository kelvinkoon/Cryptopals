# https://cryptopals.com/sets/1/challenges/2
import binascii

INPUT_STR = "1c0111001f010100061a024b53535009181c"
INPUT_KEY = "686974207468652062756c6c277320657965"
EXPECTED_STR = "746865206b696420646f6e277420706c6179"


def decodeFixedXOR(input_bytes: bytes, key_bytes: bytes):
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


def main():
    # Decode inputs from hex
    input_bytes = binascii.unhexlify(INPUT_STR.encode("utf-8"))
    key_bytes = binascii.unhexlify(INPUT_KEY.encode("utf-8"))

    xor_bytes = decodeFixedXOR(input_bytes, key_bytes)
    # Re-encode to hex
    output_bytes = binascii.hexlify(xor_bytes).decode("utf-8")
    assert output_bytes == EXPECTED_STR


if __name__ == "__main__":
    main()
