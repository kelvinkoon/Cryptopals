# https://cryptopals.com/sets/1/challenges/1
import binascii
import base64


def convertHexToBase64(hex_enc_str: str) -> str:
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
