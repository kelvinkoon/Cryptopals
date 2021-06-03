# https://cryptopals.com/sets/2/challenges/10
import sys

sys.path.append("./")
from shared_functions import *
from challenge09 import *

BLOCK_SIZE = 16

# Refer to https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_codebook_(ECB)
def encryptAES_CBCMode(
    input_bytes: bytes, init_vector_bytes: bytes, key_bytes: bytes
) -> bytes:
    """
    Returns the bytes encrypted using AES in CBC Mode
    Assume input_bytes can be evenly broken into 16 byte blocks

    :param input_bytes The byte array to be encrypted
    :param init_vector_bytes The initialization vector for CBC Mode
    :param key_bytes The key to initialize the cipher with
    """
    bytes_blocks = breakByteArrayIntoBlocks(input_bytes, BLOCK_SIZE)

    # Initialize the ciphertext with first block and initialization vector
    prev_block = init_vector_bytes
    ciphertext_block = b""

    for i in range(0, len(bytes_blocks)):
        curr_xor_block = decodeFixedXOR(bytes_blocks[i], prev_block)
        aes_ecb_encrypt_block = encryptAES_ECBMode(curr_xor_block, key_bytes)
        prev_block = aes_ecb_encrypt_block
        ciphertext_block += aes_ecb_encrypt_block

    return ciphertext_block


# Refer to https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_codebook_(ECB)
def decryptAES_CBCMode(
    input_bytes: bytes, init_vector_bytes: bytes, key_bytes: bytes
) -> bytes:
    """
    Returns the bytes decrypted using AES in CBC Mode
    Assume input_bytes can be evenly broken into 16 byte blocks

    :param input_bytes The byte array to be decrypted
    :param init_vector_bytes The initialization vector for CBC Mode
    :param key_bytes The key to initialize the cipher with
    """
    bytes_blocks = breakByteArrayIntoBlocks(input_bytes, BLOCK_SIZE)

    # Initialize the plaintext with first block and initialization vector
    prev_block = init_vector_bytes
    plaintext_block = b""

    for i in range(0, len(bytes_blocks)):
        if len(bytes_blocks[i]) != BLOCK_SIZE:
            # Pad to 16 bytes (not to be confused with PKCS#7 padding)
            # Last input block does not fill into 16 byte block
            num_padding = BLOCK_SIZE - len(bytes_blocks[i])
            bytes_blocks[i] += b"\x00" * num_padding

        aes_ecb_decrypt_block = decryptAES_ECBMode(bytes_blocks[i], key_bytes)
        curr_xor_block = decodeFixedXOR(aes_ecb_decrypt_block, prev_block)
        prev_block = bytes_blocks[i]
        plaintext_block += curr_xor_block

    return plaintext_block
