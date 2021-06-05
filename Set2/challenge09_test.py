from Set2.challenge09 import *
import pytest

INPUT_STR1 = "YELLOW SUBMARINE"
EXPECTED_BYTES_PKCS7PADDING1 = b"YELLOW SUBMARINE\x04\x04\x04\x04"
INPUT_STR2 = "YELLOW SUBMARINE"
EXPECTED_BYTES_PKCS7PADDING2 = (
    b"YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"
)
INPUT_INVALID_PADDING_BYTES1 = b"YELLOW SUBMARINE\x04\x04\x04"
INPUT_INVALID_PADDING_BYTES2 = b"YELLOW SUBMARINE\x01\x02\x03\x04"


def test_addPKCS7PaddingOneBlock():
    ascii_bytes = INPUT_STR1.encode("utf-8")
    padded_ascii_bytes = addPKCS7Padding(ascii_bytes, 20)
    assert padded_ascii_bytes == EXPECTED_BYTES_PKCS7PADDING1


def test_addPKCS7PaddingOneBlockDivisible():
    ascii_bytes = INPUT_STR2.encode("utf-8")
    padded_ascii_bytes = addPKCS7Padding(ascii_bytes, 16)
    assert padded_ascii_bytes == EXPECTED_BYTES_PKCS7PADDING2


def test_addPKCS7PaddingMultipleBlocks():
    ascii_bytes = INPUT_STR1.encode("utf-8")
    padded_ascii_bytes = addPKCS7Padding(ascii_bytes, 4)
    assert padded_ascii_bytes == EXPECTED_BYTES_PKCS7PADDING1


def test_removePKCS7PaddingOneBlock():
    ascii_bytes = EXPECTED_BYTES_PKCS7PADDING1
    unpadded_ascii_bytes = removePKCS7Padding(ascii_bytes)
    assert unpadded_ascii_bytes == INPUT_STR1.encode("utf-8")


def test_removePKCS7PaddingOneBlock():
    ascii_bytes = EXPECTED_BYTES_PKCS7PADDING1
    unpadded_ascii_bytes = removePKCS7Padding(ascii_bytes)
    assert unpadded_ascii_bytes == INPUT_STR1.encode("utf-8")


def test_removePKCS7PaddingInvalidPadding1():
    with pytest.raises(Exception):
        removePKCS7Padding(INPUT_INVALID_PADDING_BYTES1)


def test_removePKCS7PaddingInvalidPadding2():
    with pytest.raises(Exception):
        removePKCS7Padding(INPUT_INVALID_PADDING_BYTES2)
