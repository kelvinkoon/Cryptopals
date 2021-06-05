# https://cryptopals.com/sets/2/challenges/9


def addPKCS7Padding(input_bytes: bytes, block_size: int) -> bytes:
    """
    Returns a byte array padded with PKCS#7 padding based on block size
    Note: If the input_bytes are divisible by block_size, additional padding size of len(block_size) is added

    :param input_bytes The byte array to be padded
    :param block_size The block size to be padded evenly to
    """
    # Determine amount of padding required
    num_padding = block_size - (len(input_bytes) % block_size)
    padded_bytes = input_bytes
    padded_bytes += num_padding * bytes([num_padding])

    return padded_bytes


def removePKCS7Padding(input_bytes: bytes) -> bytes:
    """
    Returns a byte array stripped of PKCS#7 padding based on block size

    :param input_bytes The byte array to be padded
    """
    # Determine number of padding bytes
    num_padding = input_bytes[-1]
    # Validate padding is correct
    if input_bytes[-1 * (num_padding) :] != num_padding * bytes([num_padding]):
        raise Exception("Padding is not correct")
    unpadded_bytes = input_bytes[: -1 * (num_padding)]

    return unpadded_bytes
