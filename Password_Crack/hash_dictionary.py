from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend 
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization 
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from encodings.base64_codec import base64_encode
from base64 import b64encode, b64decode
import random
import string
import os
import itertools
import json

PASSWORD_SPACE = ['C', 'A', 'J', 'T', 'P']

def digestSHA256(byte_user):
	myhash = hashes.SHA256()
	backend = default_backend()
	hasher = hashes.Hash(myhash, backend)
	hasher.update(byte_user)
	digest = hasher.finalize()
	return digest

def create_hash_table(n):
	#STakes an integer called n. Returns a hash table with n number or place holders (emtpy lists)
	return [[] for i in range(n)]

def foo(l):
	yield from itertools.product(*([l] * len(l)))

def randomString(stringLength):
	"""Generate a random string of fixed length """
	letters = PASSWORD_SPACE
	return ''.join(random.choice(letters) for i in range(stringLength))

def main():
	print('------------CREATING DICTIONARY ----------')
	#d = bytes.fromhex('') - use for going from hex back to bytes
	#Need to create the Dictionary - estimate size of password space
	
	password = 'TATAT' #password is all uppercase and 5 letters!!
	
	#Generate all combinations of passwords and for each combinationa.
	#with open('dictionary.json', 'w') as fp:
	with open('dictionary.txt', 'w') as file:
		file.writelines('<HASH>\t<PASSWORD> \n')
		for x in foo(password):
			val = ''.join(x)
			#Create a SHA256 hash of the value.
			digest_val = digestSHA256((val.encode()))
			#Need to write as hex or ele it will not write - Store the hash and the value to a file.
			content =  digest_val.hex() + '\t\t\t' + val + '\n'
			#Save the file, this is your dictionary
			file.writelines(content)
			#json.dump(content, fp)

	print('<DICTIONARY CREATED>')
	#Create a random 5-character password
	random_password = randomString(5) # Does it have to be within the password space??
	
	#Find the hash of the password
	hash_rand_password = digestSHA256(random_password.encode())
	
	"""
	Time how long to do each of:
	 - Search the dictionary to find the password
	 - Generate and hash all combinations in order until you find the password
	"""
	
	print('------------USING DICTIONARY TO FIND: ' + random_password+ '------------')
	


if __name__ == '__main__':
	main()
