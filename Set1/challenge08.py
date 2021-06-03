# https://cryptopals.com/sets/1/challenges/8
import binascii
from typing import List
from challenge06 import *


def detectAES_ECBMode(hex_enc_strs: List[str]) -> bytes:
    """
    Detects which line is AES-128 ECB mode by searching for duplicate 16 byte blocks
    Returns the first line thought to be encrypted with AES-128 ECB mode

    :param hex_enc_strs A list of hex-encoded strings (one of which is encoded using AES-128 ECB mode)
    """
    probable_ecb = b""
    for hex_enc_str in hex_enc_strs:
        hex_enc_str = hex_enc_str.strip()
        ascii_bytes = binascii.unhexlify(hex_enc_str.encode("utf-8"))

        # Split into 16 byte blocks
        blocks = breakByteArrayIntoBlocks(ascii_bytes, 16)
        # Check if blocks contain duplicates
        if len(blocks) != len(set(blocks)):
            probable_ecb = ascii_bytes
            break

    return probable_ecb
