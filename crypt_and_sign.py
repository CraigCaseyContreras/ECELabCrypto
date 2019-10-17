 #This python file is the combination of the code from CryptoLab1 and CryptoLab2
 #Directions: Combine your file encryption code from Crypto Lab 1 with the code from Task 3 to create an encrypted and signed file. 
 #Note it’s better to encrypt and then sign as you can verify before having to decrypt.
 
from cryptography.hazmat.backends import default_backend 
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from encodings.base64_codec import base64_encode
from binascii import unhexlify
from cryptography.hazmat.primitives.asymmetric import utils
import collections
import os
import io

fname2 = "fileToSign.txt"
file1 = open("fileToEncrypt.txt","r+")
contents = file1.read()
contents_enc = contents.encode('utf-8')
file1.close()

backend = default_backend()
salt = os.urandom(16)
idf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=16,salt=salt,iterations=100000,backend=backend)
ivval = b'MojoJojo'
iv = idf.derive(ivval)
padder = padding.PKCS7(128).padder()
unpadder = padding.PKCS7(128).unpadder()

def encrypt(contents):
	kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=16,salt=salt,iterations=100000,backend=backend)
	passwd = b'orianthi'
	key = kdf.derive(passwd)
	cipher = Cipher(algorithm=algorithms.AES(key), mode=modes.CBC(iv),backend=backend)
	encryptor = cipher.encryptor()
	mydata_pad = padder.update(contents) + padder.finalize()
	ciphertext= encryptor.update(mydata_pad) + encryptor.finalize()
	return key + ciphertext

def decrypt(contents):
	key_used = contents[:16]
	contents = contents.lstrip(contents[:16])
	#Decrypts the data - returns the original message not in bytes or hex. But in string!!!
	decryptor = Cipher(algorithm=algorithms.AES(key_used), mode=modes.CBC(iv),backend=backend).decryptor()
	plaintext = decryptor.update(contents) + decryptor.finalize()
	pt = unpadder.update(plaintext) + unpadder.finalize()
	return pt.decode()

def digestSHA256(byte_user):
	
	myhash = hashes.SHA256()
	backend = default_backend()
	hasher = hashes.Hash(myhash, backend)
	hasher.update(byte_user)
	digest = hasher.finalize()
	#print("Output of original data: ", user_input)
	return digest

def main():
	text = ""
	option = input("Type 'e' to encrypt: \t")
	#Encrypts the gettysburg
	if option == 'e':
		textt = encrypt(contents_enc)
		file3 = open(fname2, "w")
		file3.write(textt.hex()) #TRING TO WRITE AS BYTES!! REMEMBER IT IS APPARENTLY SUPPOSED TO BE IN HEX!!! change it nack when done
		file3.close()
		print("Congrats! What you encrypted is saved onto the fileToSign.txt file!")
	else:
		print("Sorry. To decrypt, you must have at least something encrypted. Please run the program and try again")
		exit()
	
	from cryptography.hazmat.primitives.asymmetric import padding #I put it here or it will give me errors
	
	myhash = hashes.SHA256()
	
	with open('fileToSign.txt') as m:
		text = m.read().encode() #Reads what is encrypted and converts the hex to bytes. So the entire thing that is inside fileToSign is actually signed
	
	#message_input = text #It is the encrypted message - the encrypted gettysburg in bytes
	#myhash = hashes.SHA256()
	#backend = default_backend()
	#hasher = hashes.Hash(myhash, backend)
	#hasher.update(message_input) # message_input MUST be in bytes!!!
	#digest = hasher.finalize()
	
	digest = digestSHA256(text)

	#Gets the private key
	password = 'hello'
	private_key = serialization.load_pem_private_key(open('kr.pem', 'rb').read(),password.encode(),default_backend())  
	pad = padding.PSS(mgf=padding.MGF1(hashes.SHA256()),  
					salt_length=padding.PSS.MAX_LENGTH)

	#Signs the padded data
	sig = private_key.sign(data=digest,
						padding=pad,
						algorithm=utils.Prehashed(myhash))

	#Saves it to a signature with .sig extension
	sig_file = 'signatureTask4' + '.sig'
	with open(sig_file, 'wb') as signature_file:
		signature_file.write(sig)

	#Loads the signature - Works it's fine 
	with open(sig_file, 'rb') as file:
		signa = file.read()

	#Use to unpad
	pad = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
	
	#Gets the public key
	public_key = serialization.load_pem_public_key(open('ku.pem', 'rb').read(),default_backend())  
	
	#Verify the signature
	try:
		public_key.verify(signature=signa,data=digest,padding=pad, algorithm=utils.Prehashed(myhash))
	except:
		print("Key is invalid!")
	else:
		print("Key is valid!")

	#Now all that is left is to decrypt the message - remember that 'textt' has the contents in bytes, not hex
	decrypted = decrypt(textt)
	with open('decryptedSignedFile.txt', 'w') as file:
		file.write(decrypted)
	
	print("Congrats! Your decrypted signed file is written onto the decryptedSignedFile.txt file!")
	
	
	
if __name__ == "__main__":
	main()
