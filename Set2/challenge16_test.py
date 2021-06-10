from Set2.challenge16 import *

EXPECTED_ENCRYPT_DECRYPT_BYTES = b"comment1=cooking%20MCs;userdata=helloworld;comment2=%20like%20a%20pound%20of%20bacon"


def test_CBCOracleEncryptDecrypt():
    cbc_oracle = CBCOracle()
    input_bytes = b"helloworld"
    ciphertext_bytes = cbc_oracle.encrypt(input_bytes)
    plaintext_bytes = cbc_oracle.decrypt(ciphertext_bytes)
    assert plaintext_bytes == EXPECTED_ENCRYPT_DECRYPT_BYTES


def test_CBCOracleMetaCharacters():
    cbc_oracle = CBCOracle()
    input_bytes = b"=hello;world"
    ciphertext_bytes = cbc_oracle.encrypt(input_bytes)
    plaintext_bytes = cbc_oracle.decrypt(ciphertext_bytes)
    assert plaintext_bytes == EXPECTED_ENCRYPT_DECRYPT_BYTES
