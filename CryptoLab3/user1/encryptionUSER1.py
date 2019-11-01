from __future__ import with_statement
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
	#data = data.encode()
	
	random_key = gen_random_key()
	iv = gen_iv()
	cipher = Cipher(algorithms.AES(random_key), modes.OFB(iv), backend=default_backend())
	encryptor = cipher.encryptor()
	ct = encryptor.update(data) + encryptor.finalize()
	return random_key + iv + ct #Random key is saved to the front of the ciphertext and iv after that. Both are size 16

def gen_random_key():
	key = os.urandom(16)
	return key

def gen_iv():

	return os.urandom(16)

def get_key_used_in_encryption(data):
	return data[:16]

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

def digestSHA256(byte_user):
	myhash = hashes.SHA256()
	backend = default_backend()
	hasher = hashes.Hash(myhash, backend)
	hasher.update(byte_user)
	digest = hasher.finalize()
	return digest


def main():
	#Create an encrypted file with a randomly generated secret key
	from cryptography.hazmat.primitives.asymmetric import padding
	pad = padding.PKCS1v15()
	with open('file_exchange_file_to_encrypt.txt', 'r') as plaintext:
		data = plaintext.read()
		data = data.encode()
	
	print('----- File to encrypt is loaded! -----')
	
	#The encryption mode I will do is OFB, since it is symmertric.
	ciphertext = encrypt_OFB(data)
	
	print('----- File is encrypted using OFB mode! -----')

	
	#Now save the ciphertext as a file
	with open('ciphertext.txt', 'wb') as file:
		file.write(ciphertext)
	
	print('----- Ciphertext contents written to ciphertext.txt! -----')
	#Encrypt the secret key used for the file encryption with the public key of user 2
	
	#First, need to get the secret key used in the encryption
	key = get_key_used_in_encryption(ciphertext)

	#Strip the key away from the ciphertext
	ciphertext = ciphertext.lstrip(ciphertext[:16])

	
	#Now re-write the ciphertext, without the key_k1 - keep the IV!!
	with open('ciphertext.txt', 'wb') as file:
		file.write(ciphertext)
	
	#Now need to get the public key of user2 - From User 2 certificate in keystore k1
	
	#The first section is the key key_k1, then the cert1, then the cert2 in keystore k1
	#The first section is the key key_k2, then the cert2, then the cert1 in keystore k2
	
	#Reads content of keystore k1
	
	certificateUSER2 = splitter('../k1.pem', 'cert2').encode()
	certUSER2 = x509.load_pem_x509_certificate(data=certificateUSER2, backend=default_backend())
	pub_keyUSER2 = certUSER2.public_key()


	print('----- Public key received from certificate!-----')
	#Encrypt the secret key used for the file encryption with the public key of user 2

	encrypted_secret_key = pub_keyUSER2.encrypt(key, pad)
	
	print('----- Encrypted secret key used for file encryption with user 2 public key! -----')
	
	#Wite the encrypted_secret_key to a file
	with open('encrypted_secret_key.txt', 'wb') as file:
		file.write(encrypted_secret_key)
	
	#Create a message digest of the encrypted file and the encrypted key
	
	#Hash data
	myhash = hashes.SHA256()
	hasher = hashes.Hash(myhash, default_backend())
	hasher.update(ciphertext)
	hasher.update(encrypted_secret_key)
	digest = hasher.finalize()
	
	#writes the digested message to a file
	with open('digested_message.txt', 'wb') as digester:
		digester.write(digest)
	
	print('----- Message digest of the encrypted file and the encrypted key created! -----')
	
	#Sign this message digest with user 1’s private key - from User 1 private key file in keystore k1'

	private_key_k1 = splitter('../k1.pem', 'priv_key').encode()
	
	private_key = serialization.load_pem_private_key(
        data=private_key_k1,
        password='hello'.encode(),
        backend=default_backend())
	
	print('----- Private key received from keystore 1! -----')
	
	#The ONLY WAY IT SIGNS IS IF THE KEY IS ENCRYPTED!!!!!!!
	sig = base64_encode(private_key.sign(data=digest,
                       padding=pad,
                       algorithm=utils.Prehashed(hashes.SHA256())))[0]


	#Saves signature
	sig_file = 'signature_done_by_user1' + '.sig'
	
	with open(sig_file, 'wb') as signature_file:
		signature_file.write(b'-----BEGIN SIGNATURE-----\n')
		signature_file.write(sig)
		signature_file.write(b'-----END SIGNATURE-----\n')
    
	print('----- Message digest signed and signature saved! -----')
	
if __name__ == '__main__':
	main()
