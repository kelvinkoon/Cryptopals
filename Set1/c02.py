import binascii
import base64

def fixedXOR(hex_str1, hex_str2):
    """
    XORs two hex strings to produce a new string
    """
    if len(hex_str1) != len(hex_str2):
        print("Input strings are not equal length")
    hex_dec1 = binascii.unhexlify(hex_str1)
    hex_dec2 = binascii.unhexlify(hex_str2)
    xor = bytes(a ^ b for (a, b) in zip(hex_dec1, hex_dec2))
    xor_hex = binascii.hexlify(xor).decode("ascii")
    return xor_hex

def main():
    hex_str1 = "1c0111001f010100061a024b53535009181c"
    hex_str2 = "686974207468652062756c6c277320657965"
    print(fixedXOR(hex_str1, hex_str2))

if __name__ == "__main__":
    main()

