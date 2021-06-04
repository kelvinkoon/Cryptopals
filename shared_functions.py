# File for commonly used functions between Challenge Sets
from Crypto.Cipher import AES
from Crypto.Hash import SHA1
from typing import List

BLOCK_SIZE_CBC = 16
BLOCK_SIZE_ECB = 16

# Testing utilities
def hashBytesToSHA1Str(input_bytes: bytes) -> str:
    h = SHA1.new()
    h.update(input_bytes)
    return h.hexdigest()

# Set 1 
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
    input_bytes = addBitPadding(input_bytes, BLOCK_SIZE_ECB)
    cipher = AES.new(key_byte, AES.MODE_ECB)
    ciphertext_bytes = cipher.encrypt(input_bytes)
    return ciphertext_bytes


def decryptAES_ECBMode(input_bytes: bytes, key_byte: bytes) -> bytes:
    """
    Returns the decrypted byte array from AES-128 in ECB mode

    :param input_bytes The byte array to decrypt
    :param key_byte The key byte to initialize the AES cipher
    """
    input_bytes = addBitPadding(input_bytes, BLOCK_SIZE_ECB)
    cipher = AES.new(key_byte, AES.MODE_ECB)
    plaintext_bytes = cipher.decrypt(input_bytes)
    return plaintext_bytes

# Set2
# Challenge 9
def addPKCS7Padding(input_bytes: bytes, block_size: int) -> bytes:
    """
    Returns a byte array padded with PKCS#7 padding based on block size
    Note: If the input_bytes are divisible by block_size, additional padding size of len(block_size) is added

    :param input_bytes The byte array to be padded
    :param block_size The block size to be padded evenly to
    """
    # Determine amount of padding required
    num_padding = block_size - (len(input_bytes) % block_size)
    padded_bytes = input_bytes
    padded_bytes += num_padding * bytes([num_padding])

    return padded_bytes

def addBitPadding(input_bytes: bytes, block_size: int) -> bytes:
    """
    Returns the byte array padded with regular bit padding to fill out block

    :param input_bytes: The byte array to be padded
    :param block_size The block size to be padded evenly to
    """
    num_padding = (block_size - len(input_bytes)) % block_size
    padded_bytes = input_bytes
    padded_bytes += num_padding * b"\x00"

    return padded_bytes

# Challenge 10
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
    input_bytes = addBitPadding(input_bytes, BLOCK_SIZE_CBC)
    bytes_blocks = breakByteArrayIntoBlocks(input_bytes, BLOCK_SIZE_CBC)

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
    input_bytes = addBitPadding(input_bytes, BLOCK_SIZE_CBC)
    bytes_blocks = breakByteArrayIntoBlocks(input_bytes, BLOCK_SIZE_CBC)

    # Initialize the plaintext with first block and initialization vector
    prev_block = init_vector_bytes
    plaintext_block = b""

    for i in range(0, len(bytes_blocks)):
        if len(bytes_blocks[i]) != BLOCK_SIZE_CBC:
            # Pad to 16 bytes (not to be confused with PKCS#7 padding)
            # Last input block does not fill into 16 byte block
            num_padding = BLOCK_SIZE_CBC - len(bytes_blocks[i])
            bytes_blocks[i] += b"\x00" * num_padding

        aes_ecb_decrypt_block = decryptAES_ECBMode(bytes_blocks[i], key_bytes)
        curr_xor_block = decodeFixedXOR(aes_ecb_decrypt_block, prev_block)
        prev_block = bytes_blocks[i]
        plaintext_block += curr_xor_block

    return plaintext_block
