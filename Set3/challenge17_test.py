from Set2.challenge16 import *
from Set3.challenge17 import *

CHALLENGE17_FILEPATH = "Set3/utils/challenge17data.txt"

def test_CBCPaddingOracleEncryptDecrypt():
	padding_oracle = CBCPaddingOracle(CHALLENGE17_FILEPATH)
	ciphertext_bytes, _ = padding_oracle.encrypt_random_str()
	assert padding_oracle.decrypt(ciphertext_bytes) == True
