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

def encrypt_OFB(data):
	#Encrypts `data` using OFB mode and PKCS#7 padding, with the given initialization vector (iv).
	
	#In OFB mode, no padding is required - one of its advantages
	
	random_key = gen_random_key()
	iv = gen_iv()
	cipher = Cipher(algorithms.AES(random_key), modes.OFB(iv), backend=default_backend())
	encryptor = cipher.encryptor()
	ct = encryptor.update(data) + encryptor.finalize()
	return random_key + ct #Random key is saved to the front of the ciphertext

def gen_random_key():
	# Just generates a random secret key using previous methods.
	
	#password = b'orianthi'
	#salt = os.urandom(16)
	#kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=16,salt=salt,iterations=100000,backend=default_backend())
	#key = kdf.derive(password)
	return os.urandom(16)

def gen_iv():
	#salt = os.urandom(16)
	#idf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=16,salt=salt,iterations=100000,backend=default_backend())
	#ivval = b'MojoJojo'
	#iv = idf.derive(ivval)
	#return iv
	return os.urandom(16)

def get_key_used_in_encryption(data):
	return data[:16]

def split(strng, sep, pos):
	strng = strng.split(sep)
	return sep.join(strng[:pos]), sep.join(strng[pos:])

def digestSHA256(byte_user):
	myhash = hashes.SHA256()
	backend = default_backend()
	hasher = hashes.Hash(myhash, backend)
	hasher.update(byte_user)
	digest = hasher.finalize()
	return digest

def main():
	#Create an encrypted file with a randomly generated secret key
	
	#So here, I would just use the encryption function and create a random file to encrypt. I will use a generate key function 

	
	#Now to encrypt a file with the random generated key. The file to encrypt is "file_exchange_file_to_encrypt.txt"
	
	with open('file_exchange_file_to_encrypt.txt', 'rb') as plaintext:
		data = plaintext.read()
	#print(data)
	
	#The encryption mode I will do is OFB, since it is symmertric.
	ciphertext = encrypt_OFB(data)
	#print(ciphertext)
	
	#Now save the ciphertext as a file
	with open('ciphertext.txt', 'wb') as file:
		file.write(ciphertext)
	
	#Encrypt the secret key used for the file encryption with the public key of user 2
	
	#First, need to get the secret key used in the encryption
	key = get_key_used_in_encryption(ciphertext)
	
	
	#Now need to get the public key of user2 - From User 2 certificate in keystore k1
	
	#The first section is the key key_k1, then the cert1, then the cert2 in keystore k1
	#The first section is the key key_k2, then the cert2, then the cert1 in keystore k2
	
	#Reads content of keystore k1
	with open('../k1.pem', 'r') as infile:
		reader = infile.read()
	
	#Gets the certificate for user2
	strng = reader
	lister = split(strng, '-----BEGIN CERTIFICATE-----', 2)
	
	#Writes what was received to a pem file for user2 certificate
	with open('user2cert.pem', 'w') as file:
		file.write("-----BEGIN CERTIFICATE-----" + lister[1])
	
	#Load the certificate for User 2
	with open('user2cert.pem', 'rb') as file:
		certificate = x509.load_pem_x509_certificate(data=file.read(), backend=default_backend())
	
	#Get public key of user2 from certificate
	public_key_user2 = certificate.public_key()
	
	#Makes the key in PEM format - easier to write to file and encrypt??
	
	#Use this ONLY to write to file!!!
	pem_pubkey_user2 = public_key_user2.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
	
	
	#Encrypt the secret key used for the file encryption with the public key of user 2

	
	#Writes them both to a .pem file to encrypt. Or should it be a txt file?
	with open('combo_seckey_and_pubkey.pem', 'wb') as file:
		file.write(key)
		file.write(pem_pubkey_user2) #needs this bcause bytes-like object needed
	
	#Just reads the contents inside to make sure
	with open('combo_seckey_and_pubkey.pem', 'rb') as infile:
		datta = infile.read()
		
	#print(datta, 'contents of the combo file \n')
	
	#Now for the encryption of the combination - encrypt using OFB??
	encrypt_combo = encrypt_OFB(datta)
	
	#Now write the encr to a file
	with open('encrypt_combo.txt', 'wb') as file:
		file.write(encrypt_combo)
	
	
	#Takes away the secret key and leaves the public key. Works fine !!
	#To decode is when we will have to convert back from bytes. Leave both as bytes until decryption!!!
	
	#keyy = get_key_used_in_encryption(encrypt_combo)
	#print(keyy, 'key from file - encrypted')
	#dattaa = encrypt_combo.lstrip(encrypt_combo[:16])
	#print(dattaa, 'key away from file - encrypted')
	
	
	#Create a message digest of the encrypted file and the encrypted key
	#So just combine ciphertext and encrypt_combo
	
	message_to_digest = ciphertext + encrypt_combo
	
	#I use a digest of SHA256
	digested_message = digestSHA256(message_to_digest)
	
	#writes the digested message to a file
	with open('digested_message.pem', 'wb') as digester:
		digester.write(digested_message)
	
	#Sign this message digest with user 1’s private key - from User 1 private key file in keystore k1
	
	from cryptography.hazmat.primitives.asymmetric import padding
	
	#Now load priv key in order to sign from keystore k1
	with open('../k1.pem', 'rb') as file:
		private_key = serialization.load_pem_private_key(
        data=file.read(), 
        password='hello'.encode(),
        backend=default_backend())
	
	pad = padding.PSS(mgf=padding.MGF1(hashes.SHA256()),  
                  salt_length=padding.PSS.MAX_LENGTH)
	
	#The ONLY WAY IT SIGNS IS IF THE KEY IS ENCRYPTED!!!!!!!
	sig = private_key.sign(data=digested_message,
                       padding=pad,
                       algorithm=utils.Prehashed(hashes.SHA256()))
	#Saves signature
	sig_file = 'signature_done_by_user1' + '.sig'
	with open(sig_file, 'wb') as signature_file:
		signature_file.write(sig)

	
if __name__ == "__main__":
	main()
