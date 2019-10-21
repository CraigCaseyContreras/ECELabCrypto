from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend 
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization 
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import utils
from encodings.base64_codec import base64_encode
from base64 import b64encode, b64decode

#Use the signing code from CryptoLab2 Task 3.1 to create a signature for a data file
print("\t----------SIGNING---------- TASK 2.1\n")
#The data file
with open('dataFile.txt', 'r') as file:
    message = file.read()

#Use the private key for User 1 as the private key for signing
password = 'hello'
private_key = serialization.load_pem_private_key(open('kr.pem', 'rb').read(),password.encode(),default_backend())  
print("----------GOT PRIVATE KEY OF USER1----------")

#Loads and hashes the data from the file
message_input = bytearray(message.encode())
myhash = hashes.SHA256()
backend = default_backend()
hasher = hashes.Hash(myhash, backend)
hasher.update(message_input)
digest = hasher.finalize()
print("----------LOADED THE HASHED DATA----------")

pad = padding.PKCS1v15()
print("----------PADDING SET----------")

#Signs the padded data
sig = private_key.sign(data=digest,
                       padding=pad,
                       algorithm=utils.Prehashed(myhash))
print("----------SIGNED PADDED DATA----------")

#Saves it to a signature with .sig extension
sig_file = 'signatureCryptoLab3' + '.sig'
with open(sig_file, 'wb') as signature_file:
	signature_file.write(sig)
print("\nCongrats! The signature has been written!\n")
    
#-------------------Use the verification code from CryptoLab2 Task 3.2 to verify the signature-------------------
print("\t----------VERIFYING----------TASK 2.2\n")
#Load the certificate for User 1
with open('user1_cert.pem', 'rb') as file:
	certificate = x509.load_pem_x509_certificate(data=file.read(), backend=backend)

#Get the public key from the certificate
public_key = certificate.public_key()

#Use the appropriate padding - padding is loaded on top

#Data is already loaded and digested since it is all in one python file with no functions

#Loads the signature
with open(sig_file, 'rb') as file:
	signa = file.read()
print("----------LOADED THE SIGNATURE----------")

#Verify the signature
print("----------VERIFYING THE SIGNATURE----------")

try:
	public_key.verify(signature=signa,data=digest,padding=pad, algorithm=utils.Prehashed(myhash))
except:
	print("Key is invalid!")
else:
	print("\nKey is valid!")
