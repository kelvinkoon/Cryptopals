# https://cryptopals.com/sets/1/challenges/1
import binascii
import base64

INPUT_STR = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
EXPECTED_STR = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"


def convertHexToBase64(hex_enc_str: str):
    """
    Converts a hex-encoded string to a base64 encoded string
    Returns a base64 encoded string

    :param hex_enc_str A hex-encoded string
    """
    # Decode hex to ASCII
    input_bytes = binascii.unhexlify(hex_enc_str.encode("utf-8"))
    # Encode ASCII to base64
    base64_bytes = base64.b64encode(input_bytes)
    # Convert from bytes to string representation
    base64_str = base64_bytes.decode("utf-8")
    return base64_str


def main():
    output_str = convertHexToBase64(INPUT_STR)
    assert output_str == EXPECTED_STR


if __name__ == "__main__":
    main()
