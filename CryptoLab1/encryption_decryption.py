import os
import io
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from encodings.base64_codec import base64_encode
from binascii import unhexlify
import collections

fname = "fileToEncrypt.txt"
fname2 = "EncryptionResult.txt"
fname3 = "fileToDecrypt.txt"
fname4 = "DecryptionResult.txt"


file1 = open("fileToEncrypt.txt","r+")
contents = file1.read()
contents = contents.encode('utf-8')
file1.close()

#file2 = open(fname2, "r+")
#ciphers = file2.read()
#file2.close()

#The things we need to do
backend = default_backend()
salt = os.urandom(16)

idf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=16,salt=salt,iterations=100000,backend=backend)

ivval = b'MojoJojo'
iv = idf.derive(ivval)


padder = padding.PKCS7(128).padder()
unpadder = padding.PKCS7(128).unpadder()

def encrypt(contents):
    #Key (length: 16) and ciphertext are in bytes but are written to the file in hex
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

def main():
	text = ""
	option = input("Type 'e' to encrypt: \t")

	if option == 'e':
		text = encrypt(contents)
		file3 = open(fname2, "w")
		file3.write(text.hex())
		file3.close()
		print("Congrats! What you encrypted is saved onto the EncryptionResult.txt file!")
	else:
		print("Sorry. To decrypt, you must have at least something encrypted. Please run the program and try again")
		exit()

	option2 = input("Now do you also want to decrypt a file, or decrypt what you just encrypted? Types 'yes' or 'no': \t")
	#print(text)
	if option2 == 'yes':
		#print(text)
		#print(ciphers)
		text = decrypt(text)
		file4 = open(fname4, "w")
		file4.write(text)
		file4.close()
		print("Congrats! What you decrypted is saved onto the DecryptionResult.txt file!")

	else:
		print("Okay! Have a good day. Thank you for using the program! Go Canes!")
		exit()


if __name__ == "__main__":
	main()

