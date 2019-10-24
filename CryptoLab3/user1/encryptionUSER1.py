from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend 
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization 
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from encodings.base64_codec import base64_encode
from base64 import b64encode, b64decode
import random
import os

def encrypt_OFB(data):
	#Encrypts `data` using OFB mode and PKCS#7 padding, with the given initialization vector (iv).
	
	padder = padding.PKCS7(128).padder()
	random_key = gen_random_key()
	iv = gen_iv()
	cipher = Cipher(algorithms.AES(random_key), modes.OFB(iv), backend=default_backend())
	encryptor = cipher.encryptor()
	mydata_pad = padder.update(data) + padder.finalize()
	ct = encryptor.update(mydata_pad) + encryptor.finalize()
	return random_key + ct #Random key is saved to the front of the ciphertext

def gen_random_key():
	# Just generates a random key of up untill length 16.
	return os.urandom(16)

def gen_iv():
	return os.urandom(16)

def get_key_used_in_encryption(data):
	key_used = data[:16]
	return key_used

def main():
	#Create an encrypted file with a randomly generated secret key
	
	#So here, I would just use the encryption function and create a random file to encrypt. I will use a generate key function 

	
	#Now to encrypt a file with the random generated key. The file to encrypt is "file_exchange_file_to_encrypt.txt"
	
	with open('file_exchange_file_to_encrypt.txt', 'rb') as plaintext:
		data = plaintext.read()
	#print(data)
	
	#The encryption mode I will do is OFB, since it is symmertric.
	ciphertext = encrypt_OFB(data)
	
	#Encrypt the secret key used for the file encryption with the public key of user 2
	
	#First, need to get the secret key used in the encryption
	key = get_key_used_in_encryption(ciphertext)
	
	#Now need to get the public key of user2 - From User 2 certificate in keystore k1
	with open('../k1.pem', 'r') as file:
		reader = file.readlines()

	
if __name__ == "__main__":
	main()
