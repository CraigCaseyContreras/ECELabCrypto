from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend 
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization 
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from encodings.base64_codec import base64_encode
from base64 import b64encode, b64decode
import random
import os

# from cryptography.hazmat.primitives import padding - might need it

def generate_certificates():
	print('\n--------LOADING CERTIFICATES FOR K1 AND K2--------')
	backend = default_backend()
	with open('user1_cert.pem', 'rb') as file:
		certificate_k1 = x509.load_pem_x509_certificate(data=file.read(), backend=backend)
		print('- K1 CERTIFICATE LOADED -')
	
	with open('user2_cert.pem', 'rb') as file:
		certificate_k2 = x509.load_pem_x509_certificate(data=file.read(), backend=backend)
		print('- K2 CERTIFICATE LOADED -')
	return (certificate_k1, certificate_k2)

def generate_keys():
	print('--------LOADING KEYS FOR K1 AND K2--------')

	password_k1 = 'hello'
	password_k2 = 'orianthi'
	
	#Private key for k1
	private_key_k1 = serialization.load_pem_private_key(open('kr.pem', 'rb').read(),password_k1.encode(),default_backend())  
	print('- K1 KEY LOADED -')
	
	#Private key for k2
	private_key_k2 = serialization.load_pem_private_key(open('kr2.pem', 'rb').read(),password_k2.encode(),default_backend())  
	print('- K2 KEY LOADED -')
	
	return (private_key_k1, private_key_k2)

def main():
	#Create two keystores, k1 and k2 with different keys to represent two users.

	#So I will just make key_for_k1 and key_for_k2 pem files

	#Generate two different private keys with different passwords
	
	#kr passwrod: hello
	#kr2 password: orianthi
	
	key1, key2 = generate_keys()
	cert1, cert2 = generate_certificates()
	
	key_k1 = key1.private_bytes(encoding = serialization.Encoding.PEM,
							 format=serialization.PrivateFormat.TraditionalOpenSSL,
							 encryption_algorithm=serialization.NoEncryption())
	
	key_k2 = key2.private_bytes(encoding = serialization.Encoding.PEM,
							format=serialization.PrivateFormat.TraditionalOpenSSL,
							encryption_algorithm=serialization.NoEncryption())
	#Makes keystore k1.pem
	with open('k1.pem', 'wb') as file:
		file.writelines([key_k1, cert1.public_bytes(serialization.Encoding.PEM), cert2.public_bytes(serialization.Encoding.PEM)])

	#Makes keystore k2.pem
	with open('k2.pem', 'wb') as file:
		file.writelines([key_k2, cert2.public_bytes(serialization.Encoding.PEM), cert1.public_bytes(serialization.Encoding.PEM)])

if __name__ == "__main__":
	main()
