# https://cryptopals.com/sets/2/challenges/11
import sys

sys.path.append("./")

from shared_functions import (
    breakByteArrayIntoBlocks,
    encryptAES_CBCMode,
    encryptAES_ECBMode,
)
import secrets
import random
from typing import Union

BLOCK_SIZE = 16


def detectECB_CBC(ciphertext_bytes: bytes) -> str:
    """
    Returns the string indicating if ciphertext has been encrypted using AES ECB or CBC mode
    Assumes if there are no repeated blocks, it is encrypted using CBC mode

    :param ciphertext_bytes The ciphertext bytes to identify the encryption mode of
    """
    blocks = breakByteArrayIntoBlocks(ciphertext_bytes, BLOCK_SIZE)
    if len(blocks) != len(set(blocks)):
        return "ECB"
    else:
        return "CBC"


def encryptECB_CBCOracle(plaintext_bytes: bytes, key_bytes: bytes) -> Union[bytes, str]:
    """
    Returns an encrypted byte array and encryption mode randomly chosen between ECB and CBC
    If CBC mode is chosen, randomly choose the initialization vector

    :param plaintext_bytes The byte array to encrypt
    :param key_bytes The key to encode
    """
    padded_plaintext_bytes = (
        secrets.token_bytes(random.randint(5, 10))
        + plaintext_bytes
        + secrets.token_bytes(random.randint(5, 10))
    )
    encrypted_bytes = b""
    encryption_mode_str = ""

    # Choose ECB or CBC encryption randomly
    if random.randint(0, 1) == 0:
        # Choose ECB encryption
        encrypted_bytes = encryptAES_ECBMode(padded_plaintext_bytes, key_bytes)
        encryption_mode_str = "ECB"
    else:
        # Choose CBC encryption
        # Generate random IV
        init_vector_bytes = secrets.token_bytes(BLOCK_SIZE)
        encrypted_bytes = encryptAES_CBCMode(
            padded_plaintext_bytes, init_vector_bytes, key_bytes
        )
        encryption_mode_str = "CBC"

    return encrypted_bytes, encryption_mode_str


def generateRandomAESKey() -> bytes:
    """
    Returns a byte array of 16 random bytes
    """
    aes_key = secrets.token_bytes(16)
    return aes_key
