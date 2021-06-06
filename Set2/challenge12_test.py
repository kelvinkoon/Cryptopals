from shared.validation_functions import *
from Set2.challenge12 import *
from Set2.challenge11 import *

PLAINTEXT_BYTES = b"A"*16
UNKNOWN_STRING = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"

def test_ECBDecryption():
    plaintext_bytes = b"A"*16
    ecb_oracle = ECBOracle()
    known_bytes = breakOracleByteAtATimeSimple(ecb_oracle)
    assert False
