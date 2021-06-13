# https://cryptopals.com/sets/2/challenges/16
from typing import Union
from Set2.challenge10 import *
from Set2.challenge11 import *
from Set1.challenge02 import *

PREPEND_STR = "comment1=cooking%20MCs;userdata="
APPEND_STR = ";comment2=%20like%20a%20pound%20of%20bacon"

# Block size provided is specified to be 16 bytes
BLOCK_SIZE = 16


class CBCOracle:
    """
    Supports encryption and decryption using CBC
    PREPEND_STR and APPEND_STR are prepended and appended to the input
    """

    def __init__(self):
        self.prepend_str = PREPEND_STR
        self.append_str = APPEND_STR
        self.random_key = generateRandomAESKey()
        self.random_iv = generateRandomAESKey()

    def encrypt(self, plaintext_bytes: bytes) -> bytes:
        """
        Performs CBC encryption on (prepend_str + plaintext + append_str)

        :param plaintext_bytes The bytes to be encrypted
        """
        # Filter metadata characters `;` and `=`
        plaintext_str = plaintext_bytes.decode("utf-8")
        if ";" in plaintext_str or "=" in plaintext_str:
            plaintext_str = plaintext_str.replace(";", "")
            plaintext_str = plaintext_str.replace("=", "")
            plaintext_bytes = plaintext_str.encode("utf-8")

        # Append/Prepend and encrypt the plaintext using CBC Mode
        target_encode_bytes = (
            self.prepend_str.encode("utf-8")
            + plaintext_bytes
            + self.append_str.encode("utf-8")
        )
        ciphertext_bytes = encryptAES_CBCModePKCS7Padded(
            target_encode_bytes, self.random_iv, self.random_key
        )

        return ciphertext_bytes

    def decryptAndCheckAdmin(self, ciphertext_bytes: bytes) -> Union[bytes, bool]:
        """
        Performs CBC decryption and checks if ";admin=true;" is present
        Returns the plaintext bytes and if ";admin=true;" is in in the plaintext

        :param ciphertext_bytes The bytes to be decrypted
        """

        # Decrypt ciphertext to plaintext bytes
        plaintext_bytes = decryptAES_CBCModePKCS7Padded(
            ciphertext_bytes, self.random_iv, self.random_key
        )

        # Check if ;admin=true; is in plaintext
        if b";admin=true;" in plaintext_bytes:
            return plaintext_bytes, True
        else:
            return plaintext_bytes, False


def executeBitFlipAttack(cbc_oracle: CBCOracle) -> bool:
    """
    Performs a bit-flip attack by manipulating ciphertext to return plaintext containing ";admin=true;"
    Given a known block's plaintext, it is possible use XOR to return ";admin=true;" plaintext
    Let C be ciphertext block, i reference which ciphertext block, P be plaintext block, and D be the AES-ECB decryption function
    Let P_i = b"A" * block_size (ie. Adversary input is a block of "A" which is known)
    C_(i-1) ^ D(C_i) = P_i
    C_(i-1) ^ D(C_i) = (b"A" * block_size)
    C_(i-1) ^ D(C_i) ^ (b"A" * block_size) ^ b";admin=true;" = b("A" * block_size) * b("A" * block_size) ^ b";admin=true"
    C_(i-1) ^ D(C_i) ^ (b"A" * block_size) ^ b";admin=true;" = b";admin=true;"
    Adversary can manipulate C_(i-1), so XOR (b"A" * block_size) and b";admin=true;" with the previous ciphertext block
    P_(i-1) will be corrupt as a result of changing C_(i-1) to manipulate P_i
    Returns whether the attack successfully created ciphertext with b";admin=true;"

    :param cbc_oracle The CBC Oracle object
    """
    # Encrypt two block of known plaintext (first block will result in garbage after bit-flip)
    input_bytes = b"A" * 2 * BLOCK_SIZE
    ciphertext_bytes = cbc_oracle.encrypt(input_bytes)
    # Save the block of C_(i-1)
    prev_ciphertext_target_block = ciphertext_bytes[2 * BLOCK_SIZE : 3 * BLOCK_SIZE]

    # Create injected bytes for C_(i-1)
    admin_bytes = b";admin=true;"
    injected_bytes = decodeFixedXOR(admin_bytes, b"A" * len(admin_bytes))

    # XOR with C_(i-1), with injected bytes arbitrarily padded since only ";admin=true;" needs to be injected properly
    ciphertext_payload_block = decodeFixedXOR(
        prev_ciphertext_target_block,
        injected_bytes + b"\x00" * (BLOCK_SIZE - len(injected_bytes)),
    )

    # Replace C_(i-1) with payload block
    blocks = breakByteArrayIntoBlocks(ciphertext_bytes, 16)
    injected_ciphertext_bytes = blocks[0] + blocks[1] + ciphertext_payload_block
    for i in range(3, len(blocks)):
        injected_ciphertext_bytes += blocks[i]

    # Decrypt and verify if ";admin=true;" is present
    _, is_admin_present = cbc_oracle.decryptAndCheckAdmin(injected_ciphertext_bytes)

    return is_admin_present
