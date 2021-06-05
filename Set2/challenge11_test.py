from Set2.challenge11 import *

NUM_ITERATIONS = 200


def test_detectECB_CBC():
    for _ in range(NUM_ITERATIONS):
        # Choose plaintext with repeating blocks
        plaintext_bytes = b"A" * 64
        random_key_bytes = generateRandomAESKey()
        random_encrypted_bytes, encryption_mode_str = encryptECB_CBCOracle(
            plaintext_bytes, random_key_bytes
        )
        encryption_mode_guess_str = detectECB_CBC(random_encrypted_bytes)
        assert encryption_mode_str == encryption_mode_guess_str
