# https://cryptopals.com/sets/1/challenges/2
import binascii

INPUT_STR = "1c0111001f010100061a024b53535009181c"
INPUT_KEY = "686974207468652062756c6c277320657965"
EXPECTED_STR = "746865206b696420646f6e277420706c6179"


def decodeFixedXOR(hex_enc_str: str, hex_enc_key: str):
    """
    Operates a fixed XOR between two strings
    Returns a hex-encoded string

    :param hex_enc_str A hex-encoded string
    :param hex_enc_key A hex-encoded string
    """
    if len(hex_enc_str) != len(hex_enc_key):
        raise Exception("Input string and key are not equal lengths")

    # Decode inputs from hex
    input_ascii_bytes = binascii.unhexlify(hex_enc_str.encode())
    key_ascii_bytes = binascii.unhexlify(hex_enc_key.encode())

    # Store individual byte XOR results
    xor_bytes = b""
    for i in range(0, len(input_ascii_bytes)):
        xor_bytes += bytes([input_ascii_bytes[i] ^ key_ascii_bytes[i]])

    # Re-encode to hex
    xor_hex_enc = binascii.hexlify(xor_bytes).decode("utf-8")
    return xor_hex_enc


def main():
    output_str = decodeFixedXOR(INPUT_STR, INPUT_KEY)
    assert output_str == EXPECTED_STR


if __name__ == "__main__":
    main()
