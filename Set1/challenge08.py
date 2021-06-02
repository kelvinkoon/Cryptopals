# https://cryptopals.com/sets/1/challenges/8
import binascii
from typing import List
from challenge06 import *

CHALLENGE08_FILEPATH = "utils/challenge08data.txt"
EXPECTED_STR = "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a"


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


def main():
    # Read from file
    input_file = open(CHALLENGE08_FILEPATH, "r")
    enc_char_strs = input_file.readlines()

    probable_ecb = detectAES_ECBMode(enc_char_strs)
    output_str = binascii.hexlify(probable_ecb).decode("utf-8")
    assert output_str == EXPECTED_STR


if __name__ == "__main__":
    main()
