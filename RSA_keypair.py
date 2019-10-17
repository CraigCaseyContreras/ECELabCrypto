from cryptography.hazmat.backends import default_backend 
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import os
import io

backend = default_backend()
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
public_key = private_key.public_key()
password = 'hello'
pem_kr = private_key.private_bytes(encoding=serialization.Encoding.PEM, 
                                format=serialization.PrivateFormat.PKCS8, 
                                encryption_algorithm=serialization.BestAvailableEncryption(password.encode()))

pem_ku = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

#Now to save pem_kr to kr.pem and pem_ku to ku.pem

fname = "kr.pem"
fname2 = "ku.pem"
fnma3 = "yesy.pem"
path = os.path.abspath(fname)
path2 = os.path.abspath(fname2)

#Writing to kr.pem
#file1 = open(fname,"wb")
#file1.write(pem_kr)
#file1.close()


#How do I know if this is correct? -Did the isinstance things

with open(fname,'wb') as file:
    file.write(pem_kr)
    #private_key = serialization.load_pem_private_key(
        #data=file.read(), 
        #password=password.encode(),
        #backend=backend)
    if isinstance(private_key, rsa.RSAPrivateKey):
        print("Is a private key - can reload")


#Writing to ku.pem
#file2 = open(fname2,"wb")
#file2.write(pem_ku)
#file2.close()

with open(fname2,'wb') as file:
    file.write(pem_ku)
    #public_key = serialization.load_pem_public_key(
        #data=file.read(), 
        #backend=backend)
    if isinstance(public_key, rsa.RSAPublicKey):
        print("Is a public key - can reload")
