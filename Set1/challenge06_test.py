import sys

sys.path.append("./")

from shared_functions import *
from challenge06 import *
import base64

CHALLENGE06_FILEPATH = "Set1/utils/challenge06data.txt"
HAMMING_DIST_INPUT_STR1 = "this is a test"
HAMMING_DIST_INPUT_STR2 = "wokka wokka!!!"
EXPECTED_DISTANCE = 37
EXPECTED_HASH_HEX_STR = "5cc8909e7c4a1997091fa10851b8fb098e7f32c3"


def test_calculateHammingDistance():
    hamming_dist_bytes1 = HAMMING_DIST_INPUT_STR1.encode()
    hamming_dist_bytes2 = HAMMING_DIST_INPUT_STR2.encode()
    hamming_distance = calculateHammingDistance(
        hamming_dist_bytes1, hamming_dist_bytes2
    )
    assert hamming_distance == 37


def test_breakRepeatingKeyXOR():
    # Read file
    input_file = open(CHALLENGE06_FILEPATH, "r")
    base64_enc_str = input_file.read()
    # Decode from base64
    input_bytes = base64.b64decode(base64_enc_str)

    probable_key_bytes, _, _ = breakRepeatingKeyXOR(input_bytes)
    assert hashBytesToSHA1Str(probable_key_bytes) == EXPECTED_HASH_HEX_STR
