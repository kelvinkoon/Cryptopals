# https://cryptopals.com/sets/2/challenges/12
from Set2.challenge11 import generateRandomAESKey
from Set1.challenge06 import *
from Set1.challenge07 import *
import base64

UNKNOWN_STRING = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"

"""
AES-128-ECB(your-string || unknown-string, random-key) 
"""
class ECBOracle():
    def __init__(self):
        self.unknown_encrypted_bytes = base64.b64decode(UNKNOWN_STRING.encode("utf-8"))
        self.random_key = generateRandomAESKey()
    
    def encrypt(self, plaintext_bytes):
        ecb_input_bytes = plaintext_bytes + self.unknown_encrypted_bytes
        encrypted_bytes = encryptAES_ECBModePKCS7Padded(ecb_input_bytes, self.random_key)
        return encrypted_bytes

def breakOracleByteAtATimeSimple(ecb_oracle: ECBOracle) -> bytes:
    """
    TODO: Write Javadoc
    """
    # Feed identical bytes of known_plaintext_bytes to determine block size
    # TODO: Implement logic for determining block size
    block_size = 16

    # Decrypt unknown bytes 1-byte-at-a-time
    # Test decoding the first byte
    # first_guess_input = b"A"*15
    # first_guess = ecb_oracle.encrypt(first_guess_input) 
    # print("FIRST GUESS")
    # print(first_guess)
    # print(len(first_guess))
    # for guess_byte in range(0, 128):
    #     curr_guess_bytes = b"A"*15 + bytes([guess_byte])
    #     oracle_guess_block = ecb_oracle.encrypt(curr_guess_bytes)
    #     # print(len(oracle_guess_block))
    #     # print(bytes([guess_byte]))
    #     # print(oracle_guess_block)
    #     # print("---")
    #     if oracle_guess_block[:16] == first_guess[:16]:
    #         print("FOUND")
    #         print(bytes([guess_byte]))
    #         print(first_guess[:17])
    #         print(oracle_guess_block[:17])

    # first_find = b"R"
    # second_guess_input = b"A"*14
    # second_guess = ecb_oracle.encrypt(second_guess_input)
    # for guess_byte in range(0, 128):
    #     curr_guess_bytes = b"A"*14 + first_find + bytes([guess_byte])
    #     oracle_guess_block = ecb_oracle.encrypt(curr_guess_bytes)
    #     if oracle_guess_block[:16] == second_guess[:16]:
    #         print("FOUND AGAIN")
    #         print(bytes([guess_byte]))
    # TODO: Add logic to calculate
    num_blocks = 10
    for i in range(0, 1):
        decrypted_block = b""
        for j in range(1, block_size+1):
            # Send one-byte-short input
            one_byte_short_input_bytes = b"A"*(block_size - j) 
            one_byte_short_oracle_bytes = ecb_oracle.encrypt(one_byte_short_input_bytes) 
            # Try letters
            for guess_byte in range(0, 128):
                curr_guess_bytes = b"A"*(block_size - j) + decrypted_block + bytes([guess_byte])
                curr_guess_oracle_bytes = ecb_oracle.encrypt(curr_guess_bytes)
                # if one_byte_short_oracle_bytes[i:i+block_size + block_size] == curr_guess_oracle_bytes[i:i*block_size + block_size]:
                if one_byte_short_oracle_bytes[:16] == curr_guess_oracle_bytes[:16]:
                    print("FOUND BYTE")
                    print(bytes([guess_byte]))
                    # Add to current block result
                    print("CURR DECRYPT")
                    decrypted_block += bytes([guess_byte])
                    print(decrypted_block)
                    break

