from Set2.challenge15 import *
import pytest

INPUT_BYTES1 = b"ICE ICE BABY\x04\x04\x04\x04"
INPUT_BYTES2 = b"ICE ICE BABY\x05\x05\x05\x05"
INPUT_BYTES3 = b"ICE ICE BABY\x01\x02\x03\x04"
EXPECTED_BYTES = b"ICE ICE BABY"


def test_removePKCS7Padding():
    ascii_bytes = INPUT_BYTES1
    unpadded_ascii_bytes = removePKCS7Padding(ascii_bytes)
    assert unpadded_ascii_bytes == EXPECTED_BYTES


def test_removePKCS7PaddingInvalidSameBytes():
    with pytest.raises(Exception):
        removePKCS7Padding(INPUT_BYTES2)


def test_removePKCS7PaddingInvalidIncorrectBytes():
    with pytest.raises(Exception):
        removePKCS7Padding(INPUT_BYTES3)
