from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat

PEM	= Encoding("PEM")
PKCS1	= PublicFormat("Raw PKCS#1")

CA_NAME		= "IUDX"
CA_NAME_LOWER   = CA_NAME.lower()  
