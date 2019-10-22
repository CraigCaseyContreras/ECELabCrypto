from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime

#Gets the private key
password = 'hello'
private_key = serialization.load_pem_private_key(open('kr.pem', 'rb').read(),password.encode(),default_backend())  

#Gets the public key
public_key = serialization.load_pem_public_key(open('ku.pem', 'rb').read(),default_backend())  

#Both keys are the same one used as in CryptoLab2
print("----------PUBLIC AND PRIVATE KEYS FROM CRYPTOLAB2 RETRIEVED----------")

#Create the subject and issuer of the certificate as the same person
subject = issuer = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
                              x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Florida"),
                              x509.NameAttribute(NameOID.LOCALITY_NAME, u"Coral Gables"),
                              x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"University of Miami"),
                              x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"ECE Depti"),
                              x509.NameAttribute(NameOID.COMMON_NAME, u"User 1"),])

#Create a Certificate builder object
builder = x509.CertificateBuilder()
print("----------CERTIFICATE BUILDER OBJECT CREATED----------")

#Set the subject and issuer
builder = builder.subject_name(subject)
builder = builder.issuer_name(issuer)

#Set the date
builder = builder.not_valid_before(datetime.datetime.utcnow())
builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=10)) #Certificte is valid for 10 days

#Set a random serial number
builder = builder.serial_number(x509.random_serial_number())
print("----------SUBJECT, ISSUER, DATE, RANDOM SERIAL NUMBER SET----------")

#Add the public key
builder = builder.public_key(public_key)

#Add the basic extensions
builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True,)
print("----------ADDED PUBLIC KEY AND BASIC EXTENSIONS----------")

#Sign the certificate
certificate = builder.sign(private_key=private_key, algorithm=hashes.SHA256(),backend=default_backend())

#Save the certificate
cert_name = 'user1_cert.pem'
with open(cert_name, 'wb') as file:
	file.write(certificate.public_bytes(serialization.Encoding.PEM))

print("----------CERTIFICATE FOR USER1 SIGNED AND SAVED----------")

#-------------------------------------STUFF FOR USER 2---------------------------------------------

user2 = input("\nDo you want to do the same for user 2? Types 'yes' or 'no' \t")
if user2 == 'yes':
    #Generates a new private key for User2
	password = 'orianthi'
    
	private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

    #Generate the public key
	public_key = private_key.public_key() 
    
    #pem_kr and pem_ku stuff
	pem_kr = private_key.private_bytes(encoding=serialization.Encoding.PEM, 
                                format=serialization.PrivateFormat.PKCS8, 
                                encryption_algorithm=serialization.BestAvailableEncryption(password.encode()))
	pem_ku = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    
    #writes to pem_kr2
	with open('kr2.pem','wb') as file:
		file.write(pem_kr)

    #writes to pem_kr2
	with open('ku2.pem','wb') as file:
		file.write(pem_ku)

	#Loads private key
	private_key = serialization.load_pem_private_key(open('kr2.pem', 'rb').read(),password.encode(),default_backend())  

	#Gets the public key
	public_key = serialization.load_pem_public_key(open('ku2.pem', 'rb').read(),default_backend()) 

    #Both keys are the same one used as in CryptoLab2
	print("\n----------PUBLIC AND PRIVATE KEYS FOR USER2 GENERATED----------")

    #Create the subject and issuer of the certificate as the same person
	subject = issuer = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
                                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Florida"),
                                x509.NameAttribute(NameOID.LOCALITY_NAME, u"Coral Gables"),
                                x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"University of Miami"),
                                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"ECE Depti"),
                                x509.NameAttribute(NameOID.COMMON_NAME, u"User 2"),])

    #Create a Certificate builder object
	builder = x509.CertificateBuilder()
	print("----------CERTIFICATE BUILDER OBJECT CREATED----------")

    #Set the subject and issuer
	builder = builder.subject_name(subject)
	builder = builder.issuer_name(issuer)

    #Set the date - THINK THERE IS SOMETHING WRONG WITH THE CODE HERE???
	builder = builder.not_valid_before(datetime.datetime.utcnow())
	builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=10)) #Certificte is valid for 10 days

    #Set a random serial number
	builder = builder.serial_number(x509.random_serial_number())
	print("----------SUBJECT, ISSUER, DATE, RANDOM SERIAL NUMBER SET----------")

    #Add the public key
	builder = builder.public_key(public_key)

    #Add the basic extensions
	builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True,)
	print("----------ADDED PUBLIC KEY AND BASIC EXTENSIONS----------")

    #Sign the certificate
	certificate = builder.sign(private_key=private_key, algorithm=hashes.SHA256(),backend=default_backend())

    #Save the certificate
	cert_name = 'user2_cert.pem'
	with open(cert_name, 'wb') as file:
		file.write(certificate.public_bytes(serialization.Encoding.PEM))
	print("----------CERTIFICATE FOR USER2 SIGNED AND SAVED----------")
else:
	print("Okay! Thank you!")
