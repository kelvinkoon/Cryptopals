import binascii
import base64
import string

character_frequencies = {
    'a': .08167, 'b': .01492, 'c': .02782, 'd': .04253,
    'e': .12702, 'f': .02228, 'g': .02015, 'h': .06094,
    'i': .06094, 'j': .00153, 'k': .00772, 'l': .04025,
    'm': .02406, 'n': .06749, 'o': .07507, 'p': .01929,
    'q': .00095, 'r': .05987, 's': .06327, 't': .09056,
    'u': .02758, 'v': .00978, 'w': .02360, 'x': .00150,
    'y': .01974, 'z': .00074, ' ': .13000
}

def calcBestSingleByteXOR(hex_str):
    res = {
        "key": "",
        "dec_str": "",
        "score": 0
    }

    for key in range(0, 256):
        print(decryptSingleByteXOR(hex_str, key))

def decryptSingleByteXOR(hex_str, key):
    """
    XOR against an integer
    """
    hex_dec = binascii.unhexlify(hex_str)
    curr_dec = bytes(b ^ key for b in hex_dec)
    return curr_dec

def main():
    hex_str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    calcBestSingleByteXOR(hex_str)

if __name__ == "__main__":
    main()
