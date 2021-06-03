from challenge04 import *

CHALLENGE04_FILEPATH = "Set1/utils/challenge04data.txt"
EXPECTED_STR = "7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f"
EXPECTED_DECODED_BYTES = b"Now that the party is jumping\n"


def test_detectSingleCharXOR():
    # Read from file
    input_file = open(CHALLENGE04_FILEPATH, "r")
    enc_char_strs = input_file.readlines()

    xor_str, probable_ascii_bytes, _, _ = detectSingleCharXOR(enc_char_strs)
    assert xor_str.strip() == EXPECTED_STR.strip()
    assert probable_ascii_bytes.decode("utf-8") == EXPECTED_DECODED_BYTES.decode(
        "utf-8"
    )
