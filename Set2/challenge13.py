# https://cryptopals.com/sets/2/challenges/13
from Set2.challenge11 import generateRandomAESKey
from Set1.challenge07 import *


def parseProfileCookie(cookie_str: str) -> dict[str, str]:
    """
    TODO: Javadoc
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
    TODO: Javadoc
    """

    def __init__(self):
        self.random_key = generateRandomAESKey()
        self.curr_uid = 10
        self.default_role = "user"

    def createProfile(self, email_str: str) -> str:
        # Remove `&` and `=`
        if "&" in email_str:
            email_str = email_str.replace("&", "")

        if "=" in email_str:
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

    def encrypt(self, plaintext_profile_str) -> bytes:
        # TODO: Javadoc
        plaintext_profile_bytes = plaintext_profile_str.encode("utf-8")
        encrypted_profile_bytes = encryptAES_ECBModePKCS7Padded(
            plaintext_profile_bytes, self.random_key
        )
        return encrypted_profile_bytes

    def decrypt(self, encoded_profile_bytes) -> bytes:
        # TODO: Javadoc
        decrypted_profile_bytes = decryptAES_ECBModePKCS7Padded(
            encoded_profile_bytes, self.random_key
        )
        plaintext_profile_str = decrypted_profile_bytes.decode("utf-8")
        return plaintext_profile_str


def executeECBCutAndPaste():
    # TODO: Javadoc
    # TODO: Input "admin" as username and encrypt block
    # TODO: Replace "user" block with newly encrypted "admin" block
    profile_oracle = ProfileOracle()
