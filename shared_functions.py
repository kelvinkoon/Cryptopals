# File for commonly used functions between Challenge Sets
from Crypto.Cipher import AES
from typing import List

# Set 1 Functions
# Challenge 2
def decodeFixedXOR(input_bytes: bytes, key_bytes: bytes) -> bytes:
    """
    Operates a fixed XOR between two byte arrays
    Returns a fixed XOR byte array

    :param input_bytes Byte array to decode
    :param key_bytes Byte array acting as key
    """
    if len(input_bytes) != len(key_bytes):
        raise Exception("Input string and key are not equal lengths")

    # Store individual byte XOR results
    xor_bytes = b""
    for i in range(0, len(input_bytes)):
        xor_bytes += bytes([input_bytes[i] ^ key_bytes[i]])

    return xor_bytes

# Challenge 6
def breakByteArrayIntoBlocks(input_bytes: bytes, block_size: int) -> List[bytes]:
    """
    Break byte array into blocks of specified length
    Returns a list of byte arrays

    :param input_bytes The bytes to be "blockified"
    :param block_size Size of the blocks
    """
    blocks = []
    num_blocks = len(input_bytes) // block_size
    # Add additional block for remaining bytes
    if len(input_bytes) % block_size != 0:
        num_blocks += 1
    for i in range(0, num_blocks):
        curr_block = takeBlock(input_bytes, i * block_size, i * block_size + block_size)
        blocks.append(curr_block)

    return blocks

def takeBlock(input_bytes: bytes, begin: int, end: int) -> bytes:
    """
    Returns a block of bytes specified by beginning and end indices

    :param input_bytes The input byte array
    :param begin The beginning of the block
    :param end The end of the block
    """
    return input_bytes[begin:end]

# Challenge 7
def encryptAES_ECBMode(input_bytes: bytes, key_byte: bytes) -> bytes:
    """
    Returns the encrypted byte array from AES-128 in ECB mode

    :param input_bytes The byte array to encrypt
    :param key_byte The key byte to initialize the AES cipher
    """
    cipher = AES.new(key_byte, AES.MODE_ECB)
    ciphertext_bytes = cipher.encrypt(input_bytes)
    return ciphertext_bytes


def decryptAES_ECBMode(input_bytes: bytes, key_byte: bytes) -> bytes:
    """
    Returns the decrypted byte array from AES-128 in ECB mode

    :param input_bytes The byte array to decrypt
    :param key_byte The key byte to initialize the AES cipher
    """
    cipher = AES.new(key_byte, AES.MODE_ECB)
    plaintext_bytes = cipher.decrypt(input_bytes)
    return plaintext_bytes
