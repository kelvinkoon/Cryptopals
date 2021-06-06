# https://cryptopals.com/sets/2/challenges/12
from Set2.challenge11 import generateRandomAESKey
from Set1.challenge06 import *
from Set1.challenge07 import *
import base64

UNKNOWN_STRING = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
BLOCK_SIZE_MAX_GUESS = 20


class ECBOracle:
    """
    An oracle using AES-ECB encryption
    Initializes with a random AES key
    encrypt() -> AES-128-ECB(your-string || unknown-string, random-key)
    """

    def __init__(self):
        self.unknown_encrypted_bytes = base64.b64decode(UNKNOWN_STRING.encode("utf-8"))
        self.random_key = generateRandomAESKey()

    def encrypt(self, plaintext_bytes):
        ecb_input_bytes = plaintext_bytes + self.unknown_encrypted_bytes
        encrypted_bytes = encryptAES_ECBModePKCS7Padded(
            ecb_input_bytes, self.random_key
        )
        return encrypted_bytes


def breakOracleByteAtATimeSimple(ecb_oracle: ECBOracle) -> bytes:
    """
    Returns the plaintext given an ECB Oracle

    :param ecb_oracle The ECBOracle object specified in the challenge
    """
    # Feed identical bytes of known_plaintext_bytes to determine block size
    # Upon reaching end of block, PKCS#7 padding will add a new block
    # The length of the new block is the block size
    block_size = 0
    prev_length_guess_oracle_bytes = len(ecb_oracle.encrypt(b"A"))
    for i in range(2, BLOCK_SIZE_MAX_GUESS):
        length_guess_input_byte = b"A" * i
        curr_length_guess_oracle_bytes = len(
            ecb_oracle.encrypt(length_guess_input_byte)
        )
        # Upon detecting a change in length, the block size is the difference thanks to padding
        if prev_length_guess_oracle_bytes != curr_length_guess_oracle_bytes:
            block_size = curr_length_guess_oracle_bytes - prev_length_guess_oracle_bytes
            break
        prev_length_guess_oracle_bytes = curr_length_guess_oracle_bytes

    # Verify oracle is using ECB mode
    ecb_guess_oracle_bytes = ecb_oracle.encrypt(b"A" * 64)
    blocks = breakByteArrayIntoBlocks(ecb_guess_oracle_bytes, block_size)
    if len(blocks) == len(set(blocks)):
        raise Exception("Oracle is not encrypting with ECB mode")

    # Ciphertext length can be calculated using block size
    # `your-string || unknown-string` where `your-string` is the block size
    oracle_guess_length = len(ecb_oracle.encrypt(b"A" * block_size))
    num_blocks = oracle_guess_length // block_size
    result_bytes = b""

    # Iterate through each block to decrypt for plaintext block
    for i in range(0, num_blocks):
        for j in range(1, block_size + 1):
            # Send one-byte-short input
            one_byte_short_input_bytes = b"A" * (block_size - j)
            one_byte_short_oracle_bytes = ecb_oracle.encrypt(one_byte_short_input_bytes)
            # Brute-force characters until one-byte-short output matches the guess's current block
            for guess_byte in range(0, 128):
                curr_guess_bytes = (
                    b"A" * (block_size - j) + result_bytes + bytes([guess_byte])
                )
                curr_guess_oracle_bytes = ecb_oracle.encrypt(curr_guess_bytes)
                if (
                    one_byte_short_oracle_bytes[
                        i * block_size : i * block_size + block_size
                    ]
                    == curr_guess_oracle_bytes[
                        i * block_size : i * block_size + block_size
                    ]
                ):
                    # Add to the resulting byte array
                    result_bytes += bytes([guess_byte])
                    break

    return removePKCS7Padding(result_bytes)
