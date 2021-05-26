# https://cryptopals.com/sets/1/challenges/2
import binascii

input_str = "1c0111001f010100061a024b53535009181c"
input_key = "686974207468652062756c6c277320657965"
expected_str = "746865206b696420646f6e277420706c6179"

def decodeFixedXOR(hex_enc_str, hex_enc_key):
    if len(hex_enc_str) != len(hex_enc_key):
        raise Exception("Input string and key are not equal lengths")

    # Decode inputs from hex
    input_ascii = binascii.unhexlify(hex_enc_str.encode())
    key_ascii = binascii.unhexlify(hex_enc_key.encode())

    # Store individual byte XOR results
    xor_bytes = []
    for i in range(0, len(input_ascii)):
        xor_byte = input_ascii[i] ^ key_ascii[i]
        xor_bytes.append(xor_byte)

    # Re-encode to hex
    xor_hex_enc = binascii.hexlify(bytearray(xor_bytes)).decode("utf-8")
    return xor_hex_enc

def main():
    output_str = decodeFixedXOR(input_str, input_key)
    assert output_str == expected_str

if __name__ == "__main__":
    main()
