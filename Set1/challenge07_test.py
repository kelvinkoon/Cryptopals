import sys

sys.path.append("./")

from shared_functions import *
from challenge07 import *
import base64

CHALLENGE07_FILEPATH = "Set1/utils/challenge07data.txt"
INPUT_KEY_STR = "YELLOW SUBMARINE"
EXPECTED_HASH_HEX_STR = "561eb43f1a2c29c7cf1ddf737e022a7bb935a1ca"


def test_decryptAES_ECBMode():
    # Read file
    input_file = open(CHALLENGE07_FILEPATH, "r")
    base64_enc_str = input_file.read()
    # Decode from base64
    ascii_bytes = base64.b64decode(base64_enc_str)
    key_bytes = INPUT_KEY_STR.encode("utf-8")

    plaintext_bytes = decryptAES_ECBMode(ascii_bytes, key_bytes)
    assert hashBytesToSHA1Str(plaintext_bytes) == EXPECTED_HASH_HEX_STR


def test_encryptAES_ECBMode():
    # Read file
    input_file = open(CHALLENGE07_FILEPATH, "r")
    base64_enc_str = input_file.read()
    # Decode from base64
    ascii_bytes = base64.b64decode(base64_enc_str)
    key_bytes = INPUT_KEY_STR.encode("utf-8")

    # Given decryption works above, encryption should reverse the process
    plaintext_bytes = decryptAES_ECBMode(ascii_bytes, key_bytes)
    ciphertext_bytes = encryptAES_ECBMode(plaintext_bytes, key_bytes)
    assert hashBytesToSHA1Str(ciphertext_bytes) == hashBytesToSHA1Str(ascii_bytes)
