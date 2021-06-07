from Set2.challenge13 import *

INPUT_COOKIE_STR = "foo=bar&baz=qux&zap=zazzle"
EXPECTED_COOKIE_OBJ = {"foo": "bar", "baz": "qux", "zap": "zazzle"}
INVALID_PROFILE_STR = "email=foo@bar.com&role=admin&uid=10&role=user"
EXPECTED_PROFILE_STR1 = "email=foo@bar.com&uid=10&role=user"


def test_parseCookie():
    cookie_obj = parseProfileCookie(INPUT_COOKIE_STR)
    assert cookie_obj == EXPECTED_COOKIE_OBJ


def test_createProfile():
    profile_oracle = ProfileOracle()
    profile_str = profile_oracle.createProfile("foo@bar.com")
    assert profile_str == EXPECTED_PROFILE_STR1


def test_createProfileInvalidChars():
    profile_oracle = ProfileOracle()
    profile_str = profile_oracle.createProfile("foo@bar.com&role=admin")
    assert profile_str != INVALID_PROFILE_STR


def test_OracleEncryptDecrypt():
    profile_oracle = ProfileOracle()
    profile_str = profile_oracle.createProfile("foo@bar.com")
    encoded_profile_bytes = profile_oracle.encrypt(profile_str)
    plaintext_profile_str = profile_oracle.decrypt(encoded_profile_bytes)
    assert plaintext_profile_str == EXPECTED_PROFILE_STR1
