import hashlib

def sha256_function(data: bytes) -> bytes:
	sha256_object = hashlib.sha256()
	sha256_object.update(data)
	return sha256_object.digest()

def sha256_trim1(data: bytes) -> bytes:
	return sha256_function(data)[:1]

def sha256_trim2(data: bytes) -> bytes:
	return sha256_function(data)[:2]
