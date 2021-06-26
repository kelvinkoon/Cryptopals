# https://cryptopals.com/sets/3/challenges/17
from Set2.challenge11 import *
from Set2.challenge10 import *
from typing import Union

class CBCPaddingOracle:
	"""
	TODO: Javadoc
	"""

	def __init__(self, FILEPATH: str):
		self.random_key = generateRandomAESKey()
		self.random_iv = generateRandomAESKey()
		self.random_strings = []

		# Populate the random strings provided
		input_file = open(FILEPATH, "r")
		rand_str_arr = input_file.readlines()

		for rand_str in rand_str_arr:
			self.random_strings.append(rand_str.strip())

	def encrypt_random_str(self) -> Union[bytes, bytes]:
		"""
		TODO: Javadoc
		"""
		# Choose random string
		rand_str = self.random_strings[random.randint(0, len(self.random_strings) - 1)]
		rand_bytes = rand_str.encode("utf-8")
		ciphertext_bytes = encryptAES_CBCModePKCS7Padded(
			rand_bytes, self.random_iv, self.random_key
		)

		return ciphertext_bytes, self.random_iv

	def decrypt(self, ciphertext_bytes: bytes, selected_iv: bytes) -> Union[bytes, bool]:
		"""
		TODO: Javadoc
		"""
		plaintext_bytes = decryptAES_CBCMode(
			ciphertext_bytes, selected_iv, self.random_key
		)

		# Validate padding is correct
		num_padding = plaintext_bytes[-1]
		if plaintext_bytes[-1 * (num_padding) :] != num_padding * bytes([num_padding]):
			return plaintext_bytes, False
		else:
			return plaintext_bytes, True

def executePaddingOracleAttack(padding_oracle: CBCPaddingOracle) -> bytes:
	# TODO: Mark the return type hints
	# Generate the ciphertext
	ciphertext_bytes, _ = padding_oracle.encrypt_random_str()
	print(ciphertext_bytes)
	print(len(ciphertext_bytes))

	c2 = ciphertext_bytes[:16]
	random_bytes = secrets.token_bytes(15)

	for key in range(0, 256):
		c1 = random_bytes +  bytes([key])
		plaintext_bytes, valid = padding_oracle.decrypt(c2, c1)
		print(plaintext_bytes)
		if valid:
			print("SUCCESS")
			print(key)
			break
		print(c1)
		print("---")

	return "a"
