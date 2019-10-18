from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from datetime import datetime, timedelta

#Gets the private key
password = 'hello'
private_key = serialization.load_pem_private_key(open('kr.pem', 'rb').read(),password.encode(),default_backend())  
pad = padding.PSS(mgf=padding.MGF1(hashes.SHA256()),  
                salt_length=padding.PSS.MAX_LENGTH)

#Gets the public key
public_key = serialization.load_pem_public_key(open('ku.pem', 'rb').read(),default_backend())  

#Both keys are the same one used as in CryptoLab2

#Create the subject and issuer of the certificate as the same person
subject = issuer = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
                              x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Florida"),
                              x509.NameAttribute(NameOID.LOCALITY_NAME, u"Coral Gables"),
                              x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"University of Miami"),
                              x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"ECE Depti"),
                              x509.NameAttribute(NameOID.COMMON_NAME, u"User 1"),])

#Create a Certificate builder object
builder = x509.CertificateBuilder()

#Set the subject and issuer
builder = builder.subject_name(subject)
builder = builder.issuer_name(issuer)

#Set the date - THINK THERE IS SOMETHING WRONG WITH THE CODE HERE???
builder = builder.not_valid_before(datetime.datetime.today() - datetime.timedelta(days=1))
builder = builder.not_valid_after(datetime.datetime(2018, 8, 2))

#Set a random serial number
builder = builder.serial_number(x509.random_serial_number())

#Add the public key
builder = builder.public_key(public_key)

#Add the basic extensions
builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True,)

#Sign the certificate
certificate = builder.sign(private_key=private_key, algorithm=hashes.SHA256(),backend=default_backend())

#Save the certificate
cert_name = 'user1_cert.pem'
with open(cert_name, 'wb') as file:
	file.write(certificate.public_bytes(serialization.Encoding.PEM))
