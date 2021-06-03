# https://cryptopals.com/sets/2/challenges/9


def addPKCS7Padding(input_bytes: bytes, block_size: int) -> bytes:
    """
    Returns the byte array padded with PKCS#7 padding based on block size

    :param input_bytes The byte array to be padded
    :param block_size The block size to be padded evenly to
    """
    # Determine amount of padding required
    num_padding = block_size - (len(input_bytes) % block_size)
    padded_bytes = input_bytes
    padded_bytes += num_padding * bytes([num_padding])

    return padded_bytes
