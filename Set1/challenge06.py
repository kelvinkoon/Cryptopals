# https://cryptopals.com/sets/1/challenges/6
from challenge03 import *
from typing import List, Union
import base64

CHALLENGE06_FILEPATH = "util/challenge06data.txt"
HAMMING_DIST_INPUT_STR1 = "this is a test"
HAMMING_DIST_INPUT_STR2 = "wokka wokka!!!"
EXPECTED_DISTANCE = 37
EXPECTED_KEY_STR = "Terminator X: Bring the noise"

GUESS_LEN = 40


def calculateHammingDistance(input_bytes1: bytes, input_bytes2: bytes) -> int:
    """
    Returns the Hamming Distance between two byte arrays

    :param input_bytes1 The first byte array to be compared
    :param input_bytes2 The second byte array to be compared
    """
    if len(input_bytes1) != len(input_bytes2):
        raise Exception("Byte arrays must be the same length")

    distance = 0
    for i in range(len(input_bytes1)):
        # Convert byte to bit string
        input_bits1 = "{0:b}".format(input_bytes1[i]).zfill(8)
        input_bits2 = "{0:b}".format(input_bytes2[i]).zfill(8)

        # Calculate distance for byte
        for j in range(len(input_bits1)):
            if input_bits1[j] != input_bits2[j]:
                distance += 1

    return distance


def takeBlock(input_bytes: bytes, begin: int, end: int) -> bytes:
    """
    Returns a block of bytes specified by beginning and end indices

    :param input_bytes The input byte array
    :param begin The beginning of the block
    :param end The end of the block
    """
    return input_bytes[begin:end]


def breakByteArrayIntoBlocks(input_bytes: bytes, block_size: int) -> List[bytes]:
    """
    Break byte array into blocks of specified length
    Returns a list of byte arrays

    :param input_bytes The bytes to be "blockified"
    :param block_size Size of the blocks
    """
    blocks = []
    num_blocks = len(input_bytes) // block_size
    # Add additional block for remaining bytes
    if len(input_bytes) % block_size != 0:
        num_blocks += 1
    for i in range(0, num_blocks):
        curr_block = takeBlock(input_bytes, i * block_size, i * block_size + block_size)
        blocks.append(curr_block)

    return blocks


def breakRepeatingKeyXOR(input_bytes: bytes) -> Union[bytes, int, int]:
    """
    Returns the probable key bytes, probable keysize, and "likelihood" score

    :param input_bytes The byte array to retrieve key from
    """

    # Attempt range of key sizes
    key_size_distances = {}
    for keysize in range(2, GUESS_LEN + 1):
        # Take 4 key size of bytes
        keysize_chunks = []
        for i in range(0, 4):
            curr_chunk = takeBlock(input_bytes, i * keysize, i * keysize + keysize)
            keysize_chunks.append(curr_chunk)

        # Average distances between chunks and normalize by keysize
        avg_distance = 0
        num_combinations = 0
        # Calculate all possible distances between chunks
        for i in range(len(keysize_chunks) - 1):
            for j in range(i + 1, len(keysize_chunks)):
                avg_distance += calculateHammingDistance(
                    keysize_chunks[i], keysize_chunks[j]
                )
                num_combinations += 1
        # Average and normalize distance
        avg_distance /= num_combinations
        norm_distance = avg_distance / keysize
        key_size_distances[keysize] = norm_distance

    # Sort keys by lowest distance
    s_key_size_distances = sorted(key_size_distances.items(), key=lambda x: x[1])
    # Select 3 best keysize candidates
    keysize_candidates = [keysize_dist[0] for keysize_dist in s_key_size_distances][:3]

    # Break the cipher blocks into blocks
    blocks = breakByteArrayIntoBlocks(input_bytes, keysize_candidates[0])

    # Break XOR based on keysizes selected
    probable_score = 0
    probable_keysize = 0
    probable_key_bytes = b""
    for keysize in keysize_candidates:
        # Transpose blocks (ie. combine nth byte of all byte arrays)
        transposed_blocks = []
        for i in range(0, keysize):
            curr_transposed_block = b""
            for block in blocks:
                # Skip shorter blocks (void accessing out of bounds)
                if i < len(block):
                    curr_transposed_block += bytes([block[i]])
            transposed_blocks.append(curr_transposed_block)

        # XOR break each block and combine to form the key
        xor_key = b""
        for block in transposed_blocks:
            _, _, curr_key = decodeSingleByteXORCipher(block)
            xor_key += curr_key

        curr_score = scoreByteArray(xor_key)
        if curr_score > probable_score:
            probable_score = curr_score
            probable_keysize = keysize
            probable_key_bytes = xor_key

    return probable_key_bytes, probable_keysize, probable_score


def main():
    # Test Hamming Distance calculation
    hamming_dist_bytes1 = HAMMING_DIST_INPUT_STR1.encode()
    hamming_dist_bytes2 = HAMMING_DIST_INPUT_STR2.encode()
    hamming_distance = calculateHammingDistance(
        hamming_dist_bytes1, hamming_dist_bytes2
    )
    assert hamming_distance == 37

    # Test repeating key XOR decode
    # Read file
    input_file = open(CHALLENGE06_FILEPATH, "r")
    base64_enc_str = input_file.read()
    # Decode from base64
    input_bytes = base64.b64decode(base64_enc_str)

    probable_key_bytes, _, _ = breakRepeatingKeyXOR(input_bytes)
    output_key_str = probable_key_bytes.decode("utf-8")
    assert output_key_str == EXPECTED_KEY_STR


if __name__ == "__main__":
    main()
