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
import os

def decryptOFB(key_used, contents):
	#Remember the IV is at the start of the cphertext. Need to strip it first
	iv = contents[:16] #Get the iv
	#Strip the iv away from the ciphertext
	contents = contents.lstrip(contents[:16])
	backend = default_backend()
	decryptor = Cipher(algorithm=algorithms.AES(key_used), mode=modes.OFB(iv),backend=backend).decryptor()
	plaintext = decryptor.update(contents) + decryptor.finalize()
	return plaintext

def split(strng, sep, pos):
	strng = strng.split(sep)
	return sep.join(strng[:pos]), sep.join(strng[pos:])

def privkeyUSER2():
	writing = True
	with open('../k2.pem', 'r') as f:
		with open('outputk2.pem', 'w') as out:
			for line in f:
				if writing:
					if "-----BEGIN CERTIFICATE-----" in line:
						writing = False
					else:
						out.write(line)
				elif "-----END CERTIFICATE-----" in line:
					writing = True    

def main():
	backend = default_backend()
	#Verify the signature using user 1’s public key 

	#First need to load user 1's public key - From User 1 certificate in keystore k2
	#Reads content of keystore k2
	with open('../k2.pem', 'r') as infile:
		reader = infile.read()
		
	print('----- Loaded contents of k2! -----')
		
	#Gets the certificate for user1
	strng = reader
	lister = split(strng, '-----BEGIN CERTIFICATE-----', 2)
	
	print('----- Loaded user1 certificate! -----')
	
	#Writes what was received to a pem file for user1 certificate
	with open('user1cert.pem', 'w') as file:
		file.write("-----BEGIN CERTIFICATE-----" + lister[1])
		
	#Load the certificate for User 1
	with open('user1cert.pem', 'rb') as file:
		certificate = x509.load_pem_x509_certificate(data=file.read(), backend=default_backend())
	
	#Get public key of user1 from certificate
	public_key_user1 = certificate.public_key()
	print('----- Received public key from user1 certificate! -----')

	#Now we can verify the signature
	#Load the asymmetric padding
	from cryptography.hazmat.primitives.asymmetric import padding
	pad = padding.PKCS1v15()
	
	# --> First we must load the digested message, the PEM file one
	with open('../user1/digested_message.pem', 'rb') as file:
		digest = file.read()
	print('----- Loaded digested message! -----')

	# --> Second we need to load the signature
	with open('../user1/signature_done_by_user1.sig', 'rb') as readfile:
		signa = readfile.read()
	print('----- Loaded signature! -----')
		
	
	# --> Lastly we can verify the signature
	print("----- VERIFYING SIGNATURE -----")
	try:
		public_key_user1.verify(signature=signa,data=digest,
                       padding=pad,
                       algorithm=utils.Prehashed(hashes.SHA256()))
	except:
		print("Signature is invalid!")
	else:
		print("Signature  is valid!")
		
	#Decrypt the secret key using user 2’s private key - From User 2 private key file in keystore k2
	
	privkeyUSER2()
	print("-----DECRYPTING SECRET KEY -----")
	with open('../k2.pem', 'rb') as file:
		private_key_k2 = serialization.load_pem_private_key(
        data=file.read(), 
        password='orianthi'.encode(),
        backend=default_backend())
	
	print('----- Received user2 private key from k2! -----')
	path_encrypted_secret_key = '../user1/encrypted_secret_key.pem'
	
	#Gets the secret key used
	orig_secret_key = private_key_k2.decrypt(path_encrypted_secret_key, pad)
	
	#So to decrypt, just use the decryption of OFB function.
	#open the message
	with open('../user1/ciphertext.txt', 'rb') as file:
		contents = file.read()
	print('----- Decrypted ciphertext using OFB decryption! -----')
	plaintext = decryptOFB(orig_secret_key, contents)
	
	with open('plaintext.txt', 'w') as file:
		file.write(plaintext.decode())
	print('----- Original message written to plaintext.txt! -----')
	print(plaintext.decode())
	
	print('----- CONGRATS! -----')
	
if __name__ == "__main__":
	main()
