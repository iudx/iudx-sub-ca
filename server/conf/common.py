from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat

PEM	= Encoding("PEM")
SubjectPublicKeyInfo	= PublicFormat("X.509 subjectPublicKeyInfo with PKCS#1")

CA_NAME		= "IUDX"
CA_NAME_LOWER   = CA_NAME.lower()  
