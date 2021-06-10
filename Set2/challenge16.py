# https://cryptopals.com/sets/2/challenges/16
from Set2.challenge10 import *
from Set2.challenge11 import *

PREPEND_STR = "comment1=cooking%20MCs;userdata="
APPEND_STR = ";comment2=%20like%20a%20pound%20of%20bacon"


class CBCOracle:
    """
    Supports encryption and decryption using CBC
    PREPEND_STR and APPEND_STR are prepended and appended to the input
    Block size provided is 16 bytes
    """

    def __init__(self):
        self.prepend_str = PREPEND_STR
        self.append_str = APPEND_STR
        self.random_key = generateRandomAESKey()
        self.random_iv = generateRandomAESKey()

    def encrypt(self, plaintext_bytes: bytes):
        """
        Performs CBC encryption on (prepend_str + plaintext + append_str)

        :param plaintext_bytes The bytes to be encrypted
        """
        # Filter metadata characters `;` and `=`
        plaintext_str = plaintext_bytes.decode("utf-8")
        if ";" in plaintext_str or "=" in plaintext_str:
            plaintext_str = plaintext_str.replace(";", "")
            plaintext_str = plaintext_str.replace("=", "")
            plaintext_bytes = plaintext_str.encode("utf-8")

        # Combine and encrypt the plaintext using CBC Mode
        target_encode_bytes = (
            self.prepend_str.encode("utf-8")
            + plaintext_bytes
            + self.append_str.encode("utf-8")
        )
        ciphertext_bytes = encryptAES_CBCModePKCS7Padded(
            target_encode_bytes, self.random_iv, self.random_key
        )

        return ciphertext_bytes

    def decrypt(self, ciphertext_bytes: bytes):
        """
        Performs CBC decryption

        :param ciphertext_bytes The bytes to be decrypted
        """

        # Decrypt ciphertext to plaintext bytes
        plaintext_bytes = decryptAES_CBCModePKCS7Padded(
            ciphertext_bytes, self.random_iv, self.random_key
        )
        return plaintext_bytes
