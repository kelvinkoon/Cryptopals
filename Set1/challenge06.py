# https://cryptopals.com/sets/1/challenges/6

HAMMING_DIST_INPUT_STR1 = "this is a test"
HAMMING_DIST_INPUT_STR2 = "wokka wokka!!!"
EXPECTED_DISTANCE = 37


def convertStringToBits(input_str: str):
    """
    Returns a string representing the bits of the input string

    :param input_str The input string
    """
    # Taken courtesy of https://stackoverflow.com/questions/10237926/convert-string-to-list-of-bits-and-viceversa
    bit_str = ""
    for char in input_str:
        # Convert to binary representation
        char_bits = bin(ord(char))[2:]
        # Pad significant bits with zeros
        bit_str += char_bits.zfill(8)

    return bit_str


def calculateHammingDistance(input_str1: str, input_str2: str):
    """
    Returns the Hamming Distance between two strings

    :param input_str1 The first input string to be compared
    :param input_str2 The second input string to be compared
    """
    if len(input_str1) != len(input_str2):
        raise Exception("Strings must be the same length")

    # Convert to binary representation
    str1_bit_str = convertStringToBits(input_str1)
    str2_bit_str = convertStringToBits(input_str2)
    distance = 0

    # Count unequal bits between strings
    for i in range(0, len(str1_bit_str)):
        if str1_bit_str[i] != str2_bit_str[i]:
            distance += 1

    return distance


def main():
    hamming_distance = calculateHammingDistance(
        HAMMING_DIST_INPUT_STR1, HAMMING_DIST_INPUT_STR2
    )
    assert hamming_distance == 37


if __name__ == "__main__":
    main()
