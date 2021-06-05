from Set1.challenge07 import *
from shared.validation_functions import *
import base64

CHALLENGE07_FILEPATH = "Set1/utils/challenge07data.txt"
INPUT_KEY_STR = "YELLOW SUBMARINE"
EXPECTED_HASH_HEX_STR = "d79ec235b763289e496ac3e0972607325c3f91a6"


def test_decryptAES_ECBMode():
    # Read file
    input_file = open(CHALLENGE07_FILEPATH, "r")
    base64_enc_str = input_file.read()
    # Decode from base64
    ascii_bytes = base64.b64decode(base64_enc_str)
    key_bytes = INPUT_KEY_STR.encode("utf-8")

    plaintext_bytes = decryptAES_ECBModePKCS7Padded(ascii_bytes, key_bytes)
    assert hashBytesToSHA1Str(plaintext_bytes) == EXPECTED_HASH_HEX_STR


def test_encryptAES_ECBMode():
    # Read file
    input_file = open(CHALLENGE07_FILEPATH, "r")
    base64_enc_str = input_file.read()
    # Decode from base64
    ascii_bytes = base64.b64decode(base64_enc_str)
    key_bytes = INPUT_KEY_STR.encode("utf-8")

    # Given decryption works above, encryption should reverse the process
    plaintext_bytes = decryptAES_ECBModePKCS7Padded(ascii_bytes, key_bytes)
    ciphertext_bytes = encryptAES_ECBModePKCS7Padded(plaintext_bytes, key_bytes)
    assert hashBytesToSHA1Str(ciphertext_bytes) == hashBytesToSHA1Str(ascii_bytes)
