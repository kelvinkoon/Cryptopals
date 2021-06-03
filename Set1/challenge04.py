# https://cryptopals.com/sets/1/challenges/4
from challenge03 import *
from typing import List, Union
import binascii


def detectSingleCharXOR(enc_char_strs: List[str]) -> Union[str, bytes, int, bytes]:
    """
    Returns the encoded string, likeliest ASCII bytes, likelihood score, and likeliest key byte

    :param enc_char_strs A list of encoded strings (with one encoded using single-char XOR)
    """
    xor_str = ""
    probable_ascii_bytes = b""
    probable_score = 0
    probable_key_byte = b""

    # XOR each line for XOR likelihood
    for enc_char_str in enc_char_strs:
        enc_char_str = enc_char_str.strip()
        ascii_bytes = binascii.unhexlify(enc_char_str.encode())

        (
            curr_probable_ascii_bytes,
            curr_probable_score,
            curr_probable_key_byte,
        ) = decodeSingleByteXORCipher(ascii_bytes)

        if curr_probable_score > probable_score:
            xor_str = enc_char_str
            probable_ascii_bytes = curr_probable_ascii_bytes
            probable_score = curr_probable_score
            probable_key_byte = curr_probable_key_byte

    return xor_str, probable_ascii_bytes, probable_score, probable_key_byte
