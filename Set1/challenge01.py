# https://cryptopals.com/sets/1/challenges/1
import binascii
import base64

input_str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
expected_str = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"


def convertHexToBase64(hex_enc_str):
    """
    Converts a hex-encoded string to a base64 encoded string
    Returns a base64 encoded string

    :param hex_enc_str A hex-encoded string
    """
    # Decode hex to ASCII
    ascii_bytes = binascii.unhexlify(hex_enc_str.encode())
    # Encode ASCII to base64
    base64_bytes = base64.b64encode(ascii_bytes)
    # Convert from bytes to string representation
    base64_str = base64_bytes.decode("utf-8")
    return base64_str


def main():
    output_str = convertHexToBase64(input_str)
    assert output_str == expected_str


if __name__ == "__main__":
    main()
