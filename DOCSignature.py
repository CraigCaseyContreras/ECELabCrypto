from cryptography.hazmat.backends import default_backend 
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization 
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import utils
from encodings.base64_codec import base64_encode
from base64 import b64encode, b64decode
 
#For this, I assume that the user picked SHA256 hash function
#Remember the password is 'hello'
#The message that the user typed, I am assuming is: Hello World. I am here to destroy you!
#So I will simply recreate the hash of SHA256
 
#This loads the hashed data from task 1 - I just didn't want to write to a file and do all that. I CAN but later. Eventually
message = 'Hello World. I am here to destroy you!'
message_input = bytearray(message.encode())
myhash = hashes.SHA256()
backend = default_backend()
hasher = hashes.Hash(myhash, backend)
hasher.update(message_input)
digest = hasher.finalize()
print("----------LOADED THE HASHED DATA----------")

#Gets the private key
password = 'hello'
private_key = serialization.load_pem_private_key(open('kr.pem', 'rb').read(),password.encode(),default_backend())  
print("----------GOT PRIVATE KEY----------")

pad = padding.PSS(mgf=padding.MGF1(hashes.SHA256()),  
                  salt_length=padding.PSS.MAX_LENGTH)
print("----------PADDED DATA----------")


#Signs the padded data
sig = private_key.sign(data=digest,
                       padding=pad,
                       algorithm=utils.Prehashed(myhash))
print("----------SIGNED PADDED DATA----------")

#Saves it to a signature with .sig extension
sig_file = 'signature' + '.sig'
with open(sig_file, 'wb') as signature_file:
    signature_file.write(sig)

print("Congrats! The signature has been written!")
    
    
