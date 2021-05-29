# https://cryptopals.com/sets/1/challenges/5
import binascii

INPUT_STR = (
    "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
)
INPUT_KEY_STR = "ICE"
EXPECTED_STR = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"


def encodeRepeatingKeyXOR(input_str, input_key):
    """
    Encodes a string with a repeating key
    Returns a string encoded using a vigenere cipher

    :param input_str The input string
    :param input_key The input key
    """
    # Convert strings to byte arrays
    input_ascii_bytes = input_str.encode()
    input_key_bytes = input_key.encode()

    xor_bytes = b""
    for i in range(0, len(input_ascii_bytes)):
        # XOR with repeating key
        xor_bytes += bytes(
            [input_ascii_bytes[i] ^ input_key_bytes[i % len(input_key_bytes)]]
        )

    # Convert to hex encoding
    xor_hex_enc = binascii.hexlify(xor_bytes).decode("utf-8")

    return xor_hex_enc


def main():
    output_str = encodeRepeatingKeyXOR(INPUT_STR, INPUT_KEY_STR)
    assert output_str == EXPECTED_STR


if __name__ == "__main__":
    main()
