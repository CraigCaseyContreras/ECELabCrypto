from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

# Generate our key
key = rsa.generate_private_key(public_exponent=65537,key_size=2048,backend=default_backend())

#Decide a password (do we not need a password??)
password = b"orianthi"

# Write our key to disk for safe keeping
with open("key.pem", "wb") as f:
    f.write(key.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.TraditionalOpenSSL,encryption_algorithm=serialization.BestAvailableEncryption(password),))

#Generate a CSR
csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Florida"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"Coral Gables"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"University of Miami"),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"ECE Depti"),
    #This 'User 1' I am assuming that I put my name
    x509.NameAttribute(NameOID.COMMON_NAME, u"Craig Contreras"),
    ])).sign(key, hashes.SHA256(), default_backend())

# Write our CSR out to disk.
with open("csr.pem", "wb") as f:
    f.write(csr.public_bytes(serialization.Encoding.PEM))