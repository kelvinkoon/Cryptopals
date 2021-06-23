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

	def decrypt(self, ciphertext_bytes) -> bool:
		"""
		TODO: Javadoc
		"""
		plaintext_bytes = decryptAES_CBCMode(
			ciphertext_bytes, self.random_iv, self.random_key
		)

		# Validate padding is correct
		num_padding = plaintext_bytes[-1]
		if plaintext_bytes[-1 * (num_padding) :] != num_padding * bytes([num_padding]):
			return False
		else:
			return True
