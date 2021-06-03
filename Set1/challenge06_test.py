from challenge06 import *
import base64

CHALLENGE06_FILEPATH = "Set1/utils/challenge06data.txt"
HAMMING_DIST_INPUT_STR1 = "this is a test"
HAMMING_DIST_INPUT_STR2 = "wokka wokka!!!"
EXPECTED_DISTANCE = 37
EXPECTED_KEY_STR = "Terminator X: Bring the noise"


def test_calculateHammingDistance():
    # Test Hamming Distance calculation
    hamming_dist_bytes1 = HAMMING_DIST_INPUT_STR1.encode()
    hamming_dist_bytes2 = HAMMING_DIST_INPUT_STR2.encode()
    hamming_distance = calculateHammingDistance(
        hamming_dist_bytes1, hamming_dist_bytes2
    )
    assert hamming_distance == 37


def test_breakRepeatingKeyXOR():
    # Test repeating key XOR decode
    # Read file
    input_file = open(CHALLENGE06_FILEPATH, "r")
    base64_enc_str = input_file.read()
    # Decode from base64
    input_bytes = base64.b64decode(base64_enc_str)

    probable_key_bytes, _, _ = breakRepeatingKeyXOR(input_bytes)
    output_key_str = probable_key_bytes.decode("utf-8")
    assert output_key_str == EXPECTED_KEY_STR
