from Set2.challenge11 import *

NUM_ITERATIONS = 200


def test_detectECB_CBC():
    for _ in range(NUM_ITERATIONS):
        # Choose plaintext with repeating blocks
        plaintext_bytes = b"A" * 64
        ecb_cbc_oracle = ECB_CBCOracle()
        encrypted_oracle_bytes = ecb_cbc_oracle.encrypt(plaintext_bytes)
        encryption_mode_guess_str = detectECB_CBC(encrypted_oracle_bytes)
        assert encryption_mode_guess_str == ecb_cbc_oracle.get_EncryptionMode()
