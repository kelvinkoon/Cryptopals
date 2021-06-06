# https://cryptopals.com/sets/2/challenges/11
from shared.validation_functions import *
from Set1.challenge06 import *
from Set2.challenge10 import *
import secrets
import random
from typing import Union

BLOCK_SIZE = 16


class ECB_CBCOracle:
    """
    An oracle encrypting using ECB or CBC mode
    Encryption mode is chosen on initialization
    """

    def __init__(self):
        self.random_key = generateRandomAESKey()
        self.encryption_mode = "ECB" if random.randint(0, 1) else "CBC"

    def get_EncryptionMode(self):
        return self.encryption_mode

    def encrypt(self, plaintext_bytes):
        padded_plaintext_bytes = (
            secrets.token_bytes(random.randint(5, 10))
            + plaintext_bytes
            + secrets.token_bytes(random.randint(5, 10))
        )

        encrypted_bytes = b""
        if self.get_EncryptionMode() == "ECB":
            encrypted_bytes = encryptAES_ECBModePKCS7Padded(
                padded_plaintext_bytes, self.random_key
            )
        else:
            init_vector_bytes = secrets.token_bytes(BLOCK_SIZE)
            encrypted_bytes = encryptAES_CBCModePKCS7Padded(
                padded_plaintext_bytes, init_vector_bytes, self.random_key
            )

        return encrypted_bytes


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


def generateRandomAESKey() -> bytes:
    """
    Returns a byte array of 16 random bytes
    """
    aes_key = secrets.token_bytes(16)
    return aes_key
