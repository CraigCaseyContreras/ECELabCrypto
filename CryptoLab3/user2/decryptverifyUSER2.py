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
	#Need to load iv
	with open('../user1/iv.txt', 'rb') as file:
		iv = file.read()
	
	backend = default_backend()
	decryptor = Cipher(algorithm=algorithms.AES(key_used), mode=modes.OFB(iv),backend=backend).decryptor()
	plaintext = decryptor.update(contents) + decryptor.finalize()
	return plaintext

def splitter(fname, desired):
	with open(fname, 'r') as file:
		stringg = file.read()
		if desired == 'cert2':
			stringg_list = stringg.split('-----BEGIN CERTIFICATE-----')
			cert2_stuff = stringg_list[2]
			return '-----BEGIN CERTIFICATE-----' + cert2_stuff
		elif desired == 'priv_key':
			stringg_list0 = stringg.split('-----END ENCRYPTED PRIVATE KEY-----')
			priv_key_stuff = stringg_list0[0]
			return priv_key_stuff + '-----END ENCRYPTED PRIVATE KEY-----'

def main():
	backend = default_backend()
	
	#Verify the signature using user 1’s public key 

	#First need to load user 1's public key - From User 1 certificate in keystore k2
	#Reads content of keystore k2
	#Gets the certificate for user1
	
	certificateUSER1 = splitter('../k2.pem', 'cert2').encode()
	certUSER1 = x509.load_pem_x509_certificate(data=certificateUSER1,
                                               backend=default_backend())
	pub_keyUSER1 = certUSER1.public_key()
	
	print('----- Loaded user1 certificate! -----')
	
	print('----- Received public key from user1 certificate! -----')

	#Now we can verify the signature
	#Load the asymmetric padding
	from cryptography.hazmat.primitives.asymmetric import padding
	pad = padding.PKCS1v15()
	
	# --> First we must load the digested message, the PEM file one
	with open('../user1/digested_message.txt', 'rb') as file:
		digest = file.read()
	print('----- Loaded digested message! -----')

	# --> Second we need to load the signature
	with open('../user1/signature_done_by_user1.sig', 'rb') as readfile:
		signa = readfile.read()
	print('----- Loaded signature! -----')
		
	
	# --> Lastly we can verify the signature
	print('----- VERIFYING SIGNATURE -----')
	try:
		pub_keyUSER1.verify(signature=signa,data=digest,
                       padding=pad,
                       algorithm=utils.Prehashed(hashes.SHA256()))
	except:
		print('Signature is invalid!')
	else:
		print('Signature  is valid!')
		
	#Decrypt the secret key using user 2’s private key - From User 2 private key file in keystore k2
	
	private_key_k2 = splitter('../k2.pem', 'priv_key').encode()

	private_key_k2 = serialization.load_pem_private_key(
        data=private_key_k2,
        password='orianthi'.encode(),
        backend=default_backend())
	
	print('----- Received user2 private key from k2! -----')
	path_encrypted_secret_key = '../user1/encrypted_secret_key.txt'

	#Gets the secret key used
	orig_secret_key = private_key_k2.decrypt(path_encrypted_secret_key, pad)
	
	#So to decrypt, just use the decryption of OFB function.
	#open the message
	
	with open('../user1/ciphertext.txt', 'rb') as file: #using from that path because the ciphertext in the user2 folder doesn't change when user1 program is run.
		contents = file.read()
	print('----- Decrypted ciphertext using OFB decryption! -----')
	plaintext = decryptOFB(orig_secret_key, contents)
	
	with open('plaintext.txt', 'w') as file:
		file.write(plaintext.decode())
	print('----- Original message written to plaintext.txt! -----')
	print(plaintext.decode())
	
	print('----- CONGRATS! -----')
	
if __name__ == '__main__':
	main()
