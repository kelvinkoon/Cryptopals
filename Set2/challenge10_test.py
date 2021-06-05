from Set2.challenge10 import *
from shared.validation_functions import *
import base64

CHALLENGE10_FILEPATH = "Set2/utils/challenge10data.txt"
BLOCK_SIZE = 16
INPUT_KEY_STR = "YELLOW SUBMARINE"
INIT_VECTOR = b"\x00" * BLOCK_SIZE
EXPECTED_HASH_HEX_STR = "561eb43f1a2c29c7cf1ddf737e022a7bb935a1ca"


def test_decryptAES_CBCMode():
    # Read file
    input_file = open(CHALLENGE10_FILEPATH, "r")
    base64_enc_str = input_file.read()
    # Decode from base64
    ascii_bytes = base64.b64decode(base64_enc_str)
    key_bytes = INPUT_KEY_STR.encode("utf-8")

    # Test AES CBC Mode decryption
    plaintext_bytes = decryptAES_CBCMode(ascii_bytes, INIT_VECTOR, key_bytes)
    assert hashBytesToSHA1Str(plaintext_bytes) == EXPECTED_HASH_HEX_STR


def test_encryptAES_CBCMode():
    key_bytes = INPUT_KEY_STR.encode("utf-8")

    # Given decryption works above, encryption should reverse the process
    test_bytes = b"this is 16 bytes"
    ciphertext_bytes = encryptAES_CBCMode(test_bytes, INIT_VECTOR, key_bytes)
    plaintext_bytes = decryptAES_CBCMode(ciphertext_bytes, INIT_VECTOR, key_bytes)
    assert test_bytes == plaintext_bytes
