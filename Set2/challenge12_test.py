from shared.validation_functions import *
from Set2.challenge12 import *
from Set2.challenge11 import *

UNKNOWN_STRING = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
EXPECTED_HASH_HEX_STR = "0f7a938a0a6fc97f763710454b139317f4db7ed2"


def test_ECBDecryption():
    ecb_oracle = ECBOracle()
    plaintext_bytes = breakOracleByteAtATimeSimple(ecb_oracle)
    assert hashBytesToSHA1Str(plaintext_bytes) == EXPECTED_HASH_HEX_STR
