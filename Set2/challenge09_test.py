from challenge09 import *

INPUT_STR = "YELLOW SUBMARINE"
EXPECTED_BYTES = b"YELLOW SUBMARINE\x04\x04\x04\x04"


def test_addPKCS7Padding():
    ascii_bytes = INPUT_STR.encode("utf-8")
    padded_ascii_bytes = addPKCS7Padding(ascii_bytes, 20)
    assert padded_ascii_bytes == EXPECTED_BYTES
