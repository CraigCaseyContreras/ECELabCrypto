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
import time
import json
import csv
import pandas as pd 
import numpy as np 

def digestSHA256(byte_user):
	myhash = hashes.SHA256()
	backend = default_backend()
	hasher = hashes.Hash(myhash, backend)
	hasher.update(byte_user)
	digest = hasher.finalize()
	return digest

def foo(l):
	yield from itertools.product(*([l] * len(l)))
	
def randomPasswordUsingSpace(stringLength, space):
	"""Generate a random string of fixed length using a space"""
	pswd = ""
	pswd_size = stringLength
	alphabet = space 
	for i in range(pswd_size):
		new_letter = random.choice(alphabet)
		pswd += new_letter
	return pswd

def randomPassword(stringLength):
	"""Generate a random string of fixed length """
	pswd = ""
	pswd_size = stringLength
	alphabet = list(string.ascii_uppercase) 
	for i in range(pswd_size):
		new_letter = random.choice(alphabet)
		pswd += new_letter
	return pswd

def getPasswordSpace(password):
	return ''.join(set(password))

def createDict(password):
	print('------------CREATING DICTIONARY ----------')
	my_dict = {}
	for entryies in foo(password):
		val = ''.join(entryies)
		# print(val)
		digest_val = digestSHA256(val.encode())
		digest_val_hex = digest_val.hex()
		my_dict[digest_val_hex] = val
	with open('dictionary.csv', 'w') as f:
		for key in my_dict.keys():
			f.write("%s,%s\n"%(key,my_dict[key]))
	print('<DICTIONARY CREATED>')

def searchToFindPassword(fname, random_password):
	print('------------USING DICTIONARY TO FIND: ' + random_password+ '------------')
	#Reading the dictionary
	with open(fname) as csv_file:
		csv_reader = csv.reader(csv_file, delimiter=',')
		line_count = 0
		for row in csv_reader:
			rows = f'{" ".join(row)}'
			#Brute force search
			if random_password in rows:
				print('<PASSWORD FOUND>')
				break

def searchAndHashCombos(hash_rand_password, random_password):
	print('------------GENERATING ALL COMBOS------------')
	print('------------HASH TO FIND: ' + hash_rand_password.hex() + '------------')
	for entries in foo(random_password):
		val2 = ''.join(entries)
		digest_val2 = digestSHA256(val2.encode())
		if digest_val2 == hash_rand_password:
			print('<HASH FOUND>')
			break
def main():
	#d = bytes.fromhex('') - use for going from hex back to bytes
	#Need to create the Dictionary - estimate size of password space
	password = randomPassword(5) #password is all uppercase and 5 letters!!
	#Gets all unique characters to come up with a space
	password_space = getPasswordSpace(password)
	#Create dictionary
	createDict(password)	
	#Create a random 5-character password - using the space of the password
	random_password = randomPasswordUsingSpace(5, password_space) 
	#Find the hash of the password
	hash_rand_password = digestSHA256(random_password.encode())
	"""
	Time how long to do each of:
	 - Search the dictionary to find the password
	 - Generate and hash all combinations in order until you find the password
	"""
	searchToFindPassword('dictionary.csv', random_password)
	searchAndHashCombos(hash_rand_password, random_password)


		


if __name__ == '__main__':
	main()
