INPUT_STR = "YELLOW SUBMARINE"
EXPECTED_BYTES = b"YELLOW SUBMARINE\x04\x04\x04\x04"


def addPKCS7Padding(ascii_bytes: bytes, block_size: int):
    """
    Returns the ASCII byte array padded with PKCS#7 padding based on block size

    :param ascii_bytes The ASCII byte array to be padded
    :param block_size The block size to be padded evenly to
    """
    # Determine amount of padding required
    num_padding = block_size - (len(ascii_bytes) % block_size)
    padded_ascii_bytes = ascii_bytes
    padded_ascii_bytes += num_padding * bytes([num_padding])

    return padded_ascii_bytes


def main():
    ascii_bytes = INPUT_STR.encode("utf-8")
    padded_ascii_bytes = addPKCS7Padding(ascii_bytes, 20)
    assert padded_ascii_bytes == EXPECTED_BYTES


if __name__ == "__main__":
    main()
