from challenge02 import *
import binascii

INPUT_STR = "1c0111001f010100061a024b53535009181c"
INPUT_KEY = "686974207468652062756c6c277320657965"
EXPECTED_STR = "746865206b696420646f6e277420706c6179"


def test_decodeFixedXOR():
    # Decode inputs from hex
    input_bytes = binascii.unhexlify(INPUT_STR.encode("utf-8"))
    key_bytes = binascii.unhexlify(INPUT_KEY.encode("utf-8"))

    xor_bytes = decodeFixedXOR(input_bytes, key_bytes)
    # Re-encode to hex
    output_bytes = binascii.hexlify(xor_bytes).decode("utf-8")
    assert output_bytes == EXPECTED_STR
