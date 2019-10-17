from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding 
from cryptography.hazmat.primitives.asymmetric import utils
from encodings.base64_codec import base64_encode
        
#Gets the public key
public_key = serialization.load_pem_public_key(open('ku.pem', 'rb').read(),default_backend())  
    
#Loads the data that had to be hashed and signed
message = 'Hello World. I am here to destroy you!'
message_input = bytearray(message.encode())
myhash = hashes.SHA256()
backend = default_backend()
hasher = hashes.Hash(myhash, backend)
hasher.update(message_input)
digest = hasher.finalize()

#Loads the signature - Works it's fine 
with open('signature.sig', 'rb') as file:
    signa = file.read()

#Use to unpad
pad = padding.PSS(mgf=padding.MGF1(hashes.SHA256()),  
                  salt_length=padding.PSS.MAX_LENGTH)

#Verify the signature
try:
    public_key.verify(signature=signa,
                  data=digest,
                  padding=pad,
                  algorithm=utils.Prehashed(myhash))
except InvalidSignature as err:
    print(Fore.RED + '\nThe signature does not match!  ERROR - {!r}:'.format(err))
else:
    print("The signature is valid!")

