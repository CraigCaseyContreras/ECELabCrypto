import os
import base64

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from encodings.base64_codec import base64_encode

#print("\nUnder this are the results for TASK 2.1")
backend = default_backend()
salt = os.urandom(16)

#print(salt.hex())

kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=16,salt=salt,iterations=100000,backend=backend)
idf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=16,salt=salt,iterations=100000,backend=backend)

passwd = b'password'
ivval = b'hello'

key = kdf.derive(passwd)
iv = idf.derive(ivval)

#print(key.hex())
#print(iv.hex())
#---------------------Task 2.2----------------------------------
#print("\nUnder this are the results for TASK 2.2")
#cipher = Cipher(algorithm=algorithms.AES(key), mode=modes.CBC(iv),backend=backend)
#encryptor = cipher.encryptor()
#mydata = b'1234567812345678'
#print(mydata)
#ciphertext = encryptor.update(mydata) + encryptor.finalize() #Turns ciphertext into bytes
#print(ciphertext.hex()) #prints out the byted ciphertext into hex
#decryptor = cipher.decryptor()
#plaintext = decryptor.update(ciphertext) + decryptor.finalize()
#print(plaintext.hex())

#print("\nBase64 encoder results:")
#print(base64_encode(key))
#print(base64_encode(iv))
#print(base64_encode(ciphertext))

#---------------------Task 2.3 - 2.4-----------------------------------
print("\nUnder this are the results for TASK 2.4 ECB mode") #Also used to showcase task 2.3
cipher = Cipher(algorithm=algorithms.AES(key), mode=modes.ECB(),backend=backend)
encryptor = cipher.encryptor()
padder = padding.PKCS7(128).padder()

#mydata = b''
mydata = b'1234567890123456789012345678901212345678901234567890123456789012'
 #mydata = b'12345678'
print(len(mydata))
mydata_pad = padder.update(mydata) + padder.finalize()
print("My padded data: ",mydata_pad.hex(), len(mydata_pad.hex()))
ciphertext= encryptor.update(mydata_pad) + encryptor.finalize()
print("My ciphertext: ",ciphertext.hex(), len(ciphertext.hex()))



#Observations: Its seems as if the first padding will always be up to 32. So if the message is 16 or less, it will pad it so that the length
# is 32. In addition, once the message reaches a length of 16, it will pad up to 64.

#If length is less than 16, then it will add so that the lengh of the message becomes 16, and THEN add a padding of length 16 to give off a padded message of 32.

#If message if multiple, so like 64, still adds length of 32, then PADS 64. So length still 160.

#if message is not multiple, so 67 for example, the multiple, or size, to pad is 64. HOWEVER, adds a padding of 32 minus the mount after 64. In this case, it is 32 - 3, so adds 29. THEN adds a pading of 64
#So total length should be 160

#If the length of message is 96, it will add 32 times at the end of the message. In addition, it will add a padding of 96 so that the padding is the same size of the message.
#So whether or not the message is a not a multiple, it will add to the end until it gets to the next multiple of 32. So if message is size 17, it will add 32 - (17-16) to the message. And THEN add a padding of 32. In general, if not a multiple, adds 32 - (n-(n-1)), where n is the length of message. So if length is 65, then adds 32 - (65-64) = 31. So full "message length" is 96 + 64 to match the message size.
