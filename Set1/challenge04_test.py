from Set1.challenge04 import *
from shared.validation_functions import *

CHALLENGE04_FILEPATH = "Set1/utils/challenge04data.txt"
EXPECTED_HASH_HEX_STR = "fb3544ef78a3afde86e701a90305b489cd6a1ad6"


def test_detectSingleCharXOR():
    # Read from file
    input_file = open(CHALLENGE04_FILEPATH, "r")
    enc_char_strs = input_file.readlines()
    _, probable_ascii_bytes, _, _ = detectSingleCharXOR(enc_char_strs)

    assert hashBytesToSHA1Str(probable_ascii_bytes) == EXPECTED_HASH_HEX_STR
