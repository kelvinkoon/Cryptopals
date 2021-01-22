import binascii
import base64

def convertHexToBase64(hex_str):
    """
    Convert hex string to base64 encoding
    """
    if type(hex_str) is not str:
        print("Input is not a string")
        return "Input Error"
    hex_dec = binascii.unhexlify(hex_str)
    base64enc = base64.b64encode(hex_dec).decode("ascii")
    return base64enc

def main():
    input_str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    print(convertHexToBase64(input_str))

if __name__ == "__main__":
    main()

