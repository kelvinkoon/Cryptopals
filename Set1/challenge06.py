# https://cryptopals.com/sets/1/challenges/6
import base64

CHALLENGE06_FILEPATH = "util/challenge06data.txt"
HAMMING_DIST_INPUT_STR1 = b"this is a test"
HAMMING_DIST_INPUT_STR2 = b"wokka wokka!!!"
EXPECTED_DISTANCE = 37

GUESS_LEN = 40

def calculateHammingDistance(input_ascii_bytes1: bytes, input_ascii_bytes2: bytes):
    """
    Returns the Hamming Distance between two byte arrays

    :param input_ascii_bytes1 The first byte array to be compared
    :param input_ascii_bytes2 The second byte array to be compared
    """
    if len(input_ascii_bytes1) != len(input_ascii_bytes2):
        raise Exception("Byte arrays must be the same length")

    distance = 0
    for i in range(len(input_ascii_bytes1)):
        # Convert byte to bit string
        input_ascii_bits1 = "{0:b}".format(input_ascii_bytes1[i]).zfill(8)
        input_ascii_bits2 = "{0:b}".format(input_ascii_bytes2[i]).zfill(8)

        # Calculate distance for byte
        for j in range(len(input_ascii_bits1)):
            if input_ascii_bits1[j] != input_ascii_bits2[j]:
                distance += 1

    return distance

def takeBlock(ascii_bytes: bytes, begin: int, end: int):
    """
    Returns a block of bytes specified by beginning and end indices

    :param ascii_bytes The input ASCII byte array
    :param begin The beginning of the block
    :param end The end of the block
    """
    return ascii_bytes[begin:end]

def breakASCIIBytesIntoBlocks():
    # TODO: Implement stub
    return "a"

def breakRepeatingKeyXOR(input_path):
    """
    Returns the decoded bytes given a Vigenere-encoded base64-encoded ciphertext

    :param input_path Path to file of base64-encoded ciphertext
    """
    # Read file
    input_file = open(input_path, "r")
    base64_enc_str = input_file.read()
    # Decode from base64
    ascii_bytes = base64.b64decode(base64_enc_str)

    # Attempt range of key sizes
    key_size_distances = {}
    for keysize in range(2, GUESS_LEN+1):
        # Take 4 key size of bytes
        keysize_chunks = []
        for i in range(0, 4):
            curr_chunk = takeBlock(ascii_bytes, i*keysize, i*keysize + keysize)
            keysize_chunks.append(curr_chunk)

        # Average distances between chunks and normalize by keysize
        avg_distance = 0
        num_combinations = 0
        # Calculate all possible distances between chunks
        for i in range(len(keysize_chunks)-1):
            for j in range(i+1, len(keysize_chunks)):
                avg_distance += calculateHammingDistance(keysize_chunks[i], keysize_chunks[j])
                num_combinations += 1
        # Average and normalize
        avg_distance /= num_combinations
        norm_distance = avg_distance / keysize
        key_size_distances[keysize] = norm_distance

    # Sort keys by lowest distance
    s_key_size_distances = sorted(key_size_distances.items(), key=lambda x: x[1])
    # Select 3 best keysize candidates
    keysize_candidates = [keysize_dist[0] for keysize_dist in s_key_size_distances][:3]

    # Break the cipher blocks into blocks

    # XOR break each block


def main():
    hamming_distance = calculateHammingDistance(
        HAMMING_DIST_INPUT_STR1, HAMMING_DIST_INPUT_STR2
    )
    breakRepeatingKeyXOR(CHALLENGE06_FILEPATH)
    assert hamming_distance == 37


if __name__ == "__main__":
    main()
