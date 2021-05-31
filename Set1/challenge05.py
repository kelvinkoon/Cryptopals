# https://cryptopals.com/sets/1/challenges/5
import binascii

INPUT_STR = (
    "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
)
INPUT_KEY_STR = "ICE"
EXPECTED_STR = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"


def encodeRepeatingKeyXOR(ascii_bytes: bytes, key_bytes: bytes):
    """
    Encodes a byte array with a repeating key byte array
    Returns a byte array encoded using a vigenere cipher

    :param ascii_bytes ASCII byte array to be encoded
    :param key_bytes ASCII byte array acting as key
    """

    xor_bytes = b""
    for i in range(0, len(ascii_bytes)):
        # XOR with repeating key
        xor_bytes += bytes([ascii_bytes[i] ^ key_bytes[i % len(key_bytes)]])

    return xor_bytes


def main():
    # Convert strings to byte arrays
    input_ascii_bytes = INPUT_STR.encode()
    input_key_bytes = INPUT_KEY_STR.encode()

    xor_bytes = encodeRepeatingKeyXOR(input_ascii_bytes, input_key_bytes)
    # Convert to hex encoded string
    output_str = binascii.hexlify(xor_bytes).decode("utf-8")
    assert output_str == EXPECTED_STR


if __name__ == "__main__":
    main()
