from Set1.challenge03 import *
from shared.validation_functions import *
import binascii

INPUT_STR = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
EXPECTED_HASH_HEX_STR = "f9f8315c4cb779cb4876ddbf60c33664bdfe8723"


def test_decodeSingleByteXORcipher():
    # Decode inputs from hex
    input_bytes = binascii.unhexlify(INPUT_STR.encode())
    probable_ascii_bytes, _, _ = decodeSingleByteXORCipher(input_bytes)

    assert hashBytesToSHA1Str(probable_ascii_bytes) == EXPECTED_HASH_HEX_STR
