from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

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
