# https://cryptopals.com/sets/2/challenges/15

# Taken from Set 1 Challenge 9
def removePKCS7Padding(input_bytes: bytes) -> bytes:
    """
    Returns a byte array stripped of PKCS#7 padding based on block size
    Raise exception on invalid padding

    :param input_bytes The byte array to be padded
    """
    # Determine number of padding bytes
    num_padding = input_bytes[-1]
    # Validate padding is correct
    if input_bytes[-1 * (num_padding) :] != num_padding * bytes([num_padding]):
        raise Exception("Padding is not correct")
    unpadded_bytes = input_bytes[: -1 * (num_padding)]

    return unpadded_bytes
