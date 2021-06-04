from challenge09 import *

INPUT_STR = "YELLOW SUBMARINE"
EXPECTED_BYTES_PKCS7PADDING = b"YELLOW SUBMARINE\x04\x04\x04\x04"
EXPECTED_BYTES_BITPADDING1 = b"YELLOW SUBMARINE\x00\x00\x00\x00"
EXPECTED_BYTES_BITPADDING2 = b"YELLOW SUBMARINE"
EXPECTED_BYTES_BITPADDING3 = b"YELLOW SUBMARINE\x00\x00\x00\x00"


def test_addPKCS7Padding():
    ascii_bytes = INPUT_STR.encode("utf-8")
    padded_ascii_bytes = addPKCS7Padding(ascii_bytes, 20)
    assert padded_ascii_bytes == EXPECTED_BYTES_PKCS7PADDING


def test_addBitPadding_singleUnfilledBlock():
    ascii_bytes = INPUT_STR.encode("utf-8")
    padded_ascii_bytes = addBitPadding(ascii_bytes, 20)
    assert padded_ascii_bytes == EXPECTED_BYTES_BITPADDING1


def test_addBitPadding_singleFilledBlock():
    ascii_bytes = INPUT_STR.encode("utf-8")
    padded_ascii_bytes = addBitPadding(ascii_bytes, 16)
    assert padded_ascii_bytes == EXPECTED_BYTES_BITPADDING2


def test_addBitPadding_multipleUnfilledBlocks():
    ascii_bytes = INPUT_STR.encode("utf-8")
    padded_ascii_bytes = addBitPadding(ascii_bytes, 10)
    assert padded_ascii_bytes == EXPECTED_BYTES_BITPADDING3
