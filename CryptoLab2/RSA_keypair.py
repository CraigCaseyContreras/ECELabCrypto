from cryptography.hazmat.backends import default_backend 
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import os
import io

backend = default_backend()

#Generate the private key
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

#Generate the public key
public_key = private_key.public_key()

#Passsword used
password = 'hello'

#pem_kr and pem_ku stuff
pem_kr = private_key.private_bytes(encoding=serialization.Encoding.PEM, 
                                format=serialization.PrivateFormat.PKCS8, 
                                encryption_algorithm=serialization.BestAvailableEncryption(password.encode()))

pem_ku = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

#Now to save pem_kr to kr.pem and pem_ku to ku.pem
fname = "kr.pem"
fname2 = "ku.pem"

#Writes to pem_kr
with open(fname,'wb') as file:
    file.write(pem_kr)

#Loads it up to see if it is actually a private key and if it works
with open('kr.pem', 'rb') as file:
    private_key = serialization.load_pem_private_key(
        data=file.read(), 
        password=password.encode(),
        backend=backend)
    if isinstance(private_key, rsa.RSAPrivateKey):
        print("Is a private key - can reload")

#Writes to pem_ku
with open(fname2,'wb') as file:
    file.write(pem_ku)

#Loads the public key up and checks if it actually works
with open('ku.pem', 'rb') as file:
    public_key = serialization.load_pem_public_key(
        data=file.read(), 
        backend=backend)
    if isinstance(public_key, rsa.RSAPublicKey):
        print("Is a public key - can reload")
