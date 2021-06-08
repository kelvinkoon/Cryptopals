# https://cryptopals.com/sets/2/challenges/13
from Set2.challenge11 import generateRandomAESKey
from Set1.challenge07 import *


def parseProfileCookie(cookie_str: str) -> dict[str, str]:
    """
    Returns a profile object populated from a cookie string
    """
    cookie_obj = {}
    # Split into tokens based on `&`
    cookie_tokens = cookie_str.split("&")
    for cookie_token in cookie_tokens:
        # Retrieve field and value from token
        curr_cookie_token = cookie_token.split("=")
        curr_key = curr_cookie_token[0]
        curr_value = curr_cookie_token[1]
        cookie_obj[curr_key] = curr_value

    return cookie_obj


class ProfileOracle:
    """
    Oracle for creating profiles and encrypting/decrypting encoded profile strings
    """

    def __init__(self):
        self.random_key = generateRandomAESKey()
        self.curr_uid = 10
        self.default_role = "user"

    def createProfile(self, email_str: str) -> str:
        """
        Returns the encoded profile string
        Removes metacharacters `&` and `=`
        Effectively the `profile_for` function

        :param email_str An email address string
        """
        # Remove `&` and `=`
        if "&" in email_str or "=" in email_str:
            email_str = email_str.replace("&", "")
            email_str = email_str.replace("=", "")

        profile_str = ""
        # Add email
        profile_str += "email=" + email_str
        # Add UID
        profile_str += "&uid=" + str(self.curr_uid)
        # Add role
        profile_str += "&role=" + self.default_role

        # Increment UID for next create call
        self.curr_uid += 1

        return profile_str

    def encrypt(self, plaintext_profile_bytes: bytes) -> bytes:
        """
        Returns the AES-ECB encrypted profile bytes

        :param plaintext_profile_bytes The profile bytes to encrypt
        """
        encrypted_profile_bytes = encryptAES_ECBModePKCS7Padded(
            plaintext_profile_bytes, self.random_key
        )
        return encrypted_profile_bytes

    def decrypt(self, encoded_profile_bytes: bytes) -> bytes:
        """
        Returns the AES-ECB decrypted profile bytes

        :param encoded_profile_bytes The profile bytes to decrypt
        """
        plaintext_profile_bytes = decryptAES_ECBModePKCS7Padded(
            encoded_profile_bytes, self.random_key
        )
        return plaintext_profile_bytes


def executeECBCutAndPaste(profile_oracle: ProfileOracle) -> bytes:
    """
    Generates a ciphertext byte array through an ECB cut-and-paste attack
    `createProfile` acts as an oracle to generate usable blocks
    Returns the ciphertext byte array which decrypts to a profile with an admin role

    :param profile_oracle The ProfileOracle to create profiles and encrypt/decrypt
    """
    # Generate ciphertext where 3rd block begins with the role
    """
    1st Block: `email=abcde@foo.`
    2nd Block: `com&uid=10&role=`
    3rd Block: `user`
    """
    target_ciphertext_str = profile_oracle.createProfile("abcde@bar.com")
    target_ciphertext_bytes = target_ciphertext_str.encode("utf-8")

    # Encrypt and take first two blocks
    encrypted_target_ciphertext_bytes = profile_oracle.encrypt(target_ciphertext_bytes)
    result_block_bytes = encrypted_target_ciphertext_bytes[:32]

    # Generate ciphertext where 2nd block begins with admin role
    # Fill first block and insert second block using `createProfile`
    # Remember to account for "email=", hence 10 garbage characters
    """
    1st Block: `email=xxxxxxxxxx`
    2nd Block: `admin + b"\x0b"*11`
    3rd Block: `&uid=11&role=user`
    """
    garbage_pad_block_bytes = "a" * 10
    admin_inserted_block_bytes = "admin" + "\x0b" * 11
    admin_inserted_ciphertext_str = profile_oracle.createProfile(
        garbage_pad_block_bytes + admin_inserted_block_bytes
    )
    admin_inserted_ciphertext_bytes = admin_inserted_ciphertext_str.encode("utf-8")

    # Encrypt and take second block
    encrypted_admin_inserted_ciphertext_bytes = profile_oracle.encrypt(
        admin_inserted_ciphertext_bytes
    )
    admin_block_bytes = encrypted_admin_inserted_ciphertext_bytes[16:32]
    # Replace admin-inserted second block with target ciphertext's third block
    admin_ciphertext_bytes = result_block_bytes + admin_block_bytes
    return admin_ciphertext_bytes
