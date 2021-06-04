# https://cryptopals.com/sets/1/challenges/7
from shared_functions import addBitPadding
from Crypto.Cipher import AES

BLOCK_SIZE_ECB = 16


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
