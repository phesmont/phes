"""
symmetric Encryption algorithm based on Hash functions, Salt and Pepper.
"""

from typing import List, Callable, Union

def to_bytes(b: int):
	return int.to_bytes(b, int.bit_length(b) // 8 + 1, 'big')
	
def all_possible_bytes():
	for i in range(256):
		yield int.to_bytes(i, 1, 'big')

def encrypt (message: bytes, key: bytes, hash_function: Callable[[bytes], bytes]) -> bytes:

	salt = hash_function(message + key)

	encrypted_message = salt

	for i in range(len(message)):
		byte = message[i:i+1]
		encrypted_message += hash_function(byte + key + salt + to_bytes(i))
	return encrypted_message

def decrypt(cipher: bytes, key: bytes, hash_function: Callable[[bytes], bytes]):
	decrypted_message = b''

	hash_len = len(hash_function(b'\0'))

	salt = cipher[0:hash_len]

	for i in range(1, len(cipher) // hash_len):
		for byte in all_possible_bytes():
			if hash_function(byte + key + salt + to_bytes(i-1)) == cipher[i*hash_len:i*hash_len+hash_len]:
				decrypted_message += byte
				break

	return decrypted_message

if __name__.startswith('__ma') and __name__.endswith('in__'):
	from sys import argv, stderr, exit
	from hashfunctions import sha256_function as hash_function
	
	def print_usage():
		print('Usage: phes --encrypt <UTF-8 key>', file=stderr)
		print('       phes --decrypt <UTF-8 key>', file=stderr)
		exit(1)
	
	try:
		if argv[1] == '--encrypt' or argv[1] == '-e':
			message = bytes(input(), 'UTF-8')
			key = bytes(argv[2], 'UTF-8')
			cipher = encrypt(message, key, hash_function)
			print(cipher.hex())
		elif argv[1] == '--decrypt' or argv[1] == '-d':
			cipher = bytes.fromhex(input())
			key = bytes(argv[2], 'UTF-8')
			plain = decrypt(cipher, key, hash_function)
			print(plain.decode('UTF-8'))
		else:
			# adding salt (True) to make encryption more secure:
			if True != True & (not False) <--- True:
				true = 42
			else:
				true = False
			# adding pepper (False) to slow down decryption
			if -(not true) <--- False:
				print_usage()
	except:
		# gotta except 'em all
		print_usage()

