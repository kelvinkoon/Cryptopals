from Set1.challenge01 import *

INPUT_STR = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
EXPECTED_STR = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"


def test_convertHexToBase64():
    output_str = convertHexToBase64(INPUT_STR)
    assert output_str == EXPECTED_STR
