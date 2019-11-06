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
from encodings.base64_codec import base64_decode
import random
import string
import hashlib
import os
import itertools
import time
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
	
	write_to_csv(my_dict, 'dictionary.csv')
	return

def searchToFindPassword(fname, random_password):
	#Reading the dictionary
	with open(fname) as csv_file:
		csv_reader = csv.reader(csv_file, delimiter=',')
		line_count = 0
		for row in csv_reader:
			rows = f'{" ".join(row)}'
			#Brute force search
			if random_password in rows:
				print('<PASSWORD FOUND> \n')
				break
	return

def searchAndHashCombos(hash_rand_password, random_password):
	for entries in foo(random_password):
		val2 = ''.join(entries)
		digest_val2 = digestSHA256(val2.encode())
		if digest_val2 == hash_rand_password:
			print('<HASH FOUND>')
			break
	return

def percentage(percent, whole):
	return (percent * whole) / 100.0

def reduce(hash_value):
	'''
	Simply convert the hash value to a base- 64 representation and then take the first five characters as the generated password
	'''
	b64_representation = base64_encode(bytes.fromhex(hash_value))
	generated_password = b64_representation[0][:5] #First 5 characters
	generated_password = generated_password.decode()
	return generated_password

def rainbow_table(password):
	combosOfPasswords = list()
	indices = list()
	tables = {}
	#tables = []
	for entry in foo(password):
		vals = ''.join(entry)
		combosOfPasswords.append(vals)
	
	#So 10% of passwords rounded down is:
	ten_percent = round(percentage(10, len(combosOfPasswords)))

	#So there are ten_percent starting points, or ten_percent chains, each of length 10
	number_of_chains = ten_percent
	#Make table of index numbers to use for later
	for i in range(0,number_of_chains):
		indices.append(i)

	#Choose a random index as a starting point, then remove so that it won't be chosen again
	for loops in range(0,number_of_chains):
		index = random.choice(indices)
		indices.remove(index)
		intial = combosOfPasswords[index]
		print('Chain # ', loops+1)

		#Idea is after picking a random password - in string, to hash it, do base64, reduce and that is password2. Keep on until read password 10.
		start = intial

		for k in range(0,10):
			print('value of p: ', start)
			H = digestSHA256(start.encode())
			print('hash: ',  H)
			start = reduce(H.hex())
			print('reduced: ', start)
			print('\n\n')
			if k == 9:
				tables[intial] = start
	return tables
		
def write_to_csv(my_dict, fname):
	"""Writes a dict{} to a .csv file"""
	with open(fname, 'w') as f:
		for key in my_dict.keys():
			f.write("%s,%s\n"%(key,my_dict[key]))
	print('<',fname,'CREATED>')
	return

def read_table(fname):
	"""Read Rainbow Table from csv file"""
	dict = {}
	with open(fname, 'r') as csvfile:
		table = csv.reader(csvfile, delimiter=',', quotechar='|')
		for row in table:
			dict[str(row[0])] = str(row[1])
	return dict

def find_resultant(rainbow, r):
	#Initialize list of successors
	print(r)
	succ = [r]
	#Fills the list of successors of r
	for i in range(1,10):
		succ.append(reduce((digestSHA256(succ[i-1].encode())).hex()))
	print(succ, len(succ), 'successors')

	#Looks through the dictionary given the input
	for key, value in rainbow.items():
		if value in succ:
			print("Collision: %s -> %s" % (key, value))
			ss = key
			for i in range(0, 10):
				hash_val = digestSHA256(ss.encode())
				rs = reduce(hash_val.hex())
				#If rs == r, then key should have been found
				if rs == r:
					#Return predecessor
					return ss, value
				ss = rs

	return 

def main():
	#d = bytes.fromhex('') - use for going from hex back to bytes
	#Need to create the Dictionary - estimate size of password space
	 #password is all uppercase and 5 letters!!
	password = randomPassword(5)
	#Gets all unique characters to come up with a space
	password_space = getPasswordSpace(password)
	#Create dictionary
	createDict(password)	
	#Create a random 5-character password - using the space of the password
	random_password = randomPasswordUsingSpace(5, password_space) 
	
	#Find the hash of the password
	hash_rand_password = digestSHA256(random_password.encode())
	#hash_rand_password = hashlib.sha256(random_password.encode()).hexdigest()

	"""
	Time how long to do each of:
	 - Search the dictionary to find the password
	 - Generate and hash all combinations in order until you find the password
	"""
	print('------------USING DICTIONARY TO FIND: ' + random_password+ '------------')
	t1 = time.time()
	searchToFindPassword('dictionary.csv', random_password)
	time_spent = time.time() - t1
	print('Average time: ', time_spent, 'seconds')

	print('------------GENERATING ALL COMBOS------------')
	print('------------HASH TO FIND: ' + hash_rand_password.hex() + '------------')
	t2 = time.time()
	searchAndHashCombos(hash_rand_password, random_password)
	time_spent2 = time.time() - t2
	print('Average time: ', time_spent2, 'seconds')

	#Task 2: Create and Use a Rainbow Table
	'''
	start with chains of length 10 and using 10% of the passwords as starting points.

	1. Generate all combinations of passwords and for 10% of the combinations 
	a. Calculate the chain starting at the chosen password
	b. Record the final password
	c. Save the start and end of the chain to a file
	2. Save the file, this is your rainbow table

	'''
	print('------------CREATING RAINBOW TABLE------------')
	rainbow_dict = rainbow_table(password)
	print(rainbow_dict)
	print('length: ', len(rainbow_dict))
	write_to_csv(rainbow_dict, 'rainbow_table.csv')

	'''
	Testing the rainbow table.
	1. Create a random 5-character password
	2. Find the hash of the password
	3. Search the table:
		a. Apply the reduction on the hash
		b. Search the table to see if any chains end with the resultant value
		c. If not:
			i. Hash the new value and then return to step a
			ii. Repeat until found or you have reached the length of the chain, in which case
		the password in not in the table
		d. If found:
			i. The password you are looking for is the one that produced the hash at the point you started, i.e. the one before the hash
			ii. To find this you must look at the first password in the chain and recalculate the chain from the start to just before the hash you were looking for.
			iii. The password before this is the one you are looking for.
	4. If you do not find the password, then the table is too small, you will have to recalculate the table with more starting passwords.
	'''

	#Create a random 5-char password
	random_password2 = randomPasswordUsingSpace(5, password_space)

	#Find the hash of the password
	hash_rand_password2 = digestSHA256(random_password2.encode())

	#Apply reduction on the hash
	r = reduce(hash_rand_password2.hex())
	
	#Load the table to search through it
	loaded_rainbow = read_table('rainbow_table.csv')

	#Try to find reduction/resultant value
	if find_resultant(loaded_rainbow, r) == None:
		print('Try again. Please recalculate.')
	else:
		start_chain, end_chain = find_resultant(loaded_rainbow, r) #result, target_value interchangeable
		password_crakced = ''
		#Now hash the result until you reach the target_value.
		while start_chain != r:
			starting = start_chain
			print('\nStarting: ', starting)
			hashed = digestSHA256(start_chain.encode())
			print('Random password: ', random_password2)
			print('Hashed: ', hashed)
			print('Random password hash: ', hash_rand_password2)
			reduced = reduce(hashed.hex())
			print('Reduced: ', reduced)
			print('Random password reduced: ', r)
			start_chain = reduced
			password_crakced = starting
		print('\nThe password is: ', password_crakced)
		

if __name__ == '__main__':
	main()
