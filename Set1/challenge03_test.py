from challenge03 import *
import binascii

INPUT_STR = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
EXPECTED_DECODED_BYTES = b"Cooking MC's like a pound of bacon"
EXPECTED_KEY_BYTES = b"X"


def test_decodeSingleByteXORcipher():
    # Decode inputs from hex
    input_bytes = binascii.unhexlify(INPUT_STR.encode())

    probable_ascii_bytes, _, output_key_byte = decodeSingleByteXORCipher(input_bytes)
    assert probable_ascii_bytes.decode("utf-8") == EXPECTED_DECODED_BYTES.decode(
        "utf-8"
    )
    assert output_key_byte.decode("utf-8") == EXPECTED_KEY_BYTES.decode("utf-8")


if __name__ == "__main__":
    main()
