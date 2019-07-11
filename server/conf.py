from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat

PEM	= Encoding("PEM")
PKCS1	= PublicFormat("Raw PKCS#1")

CA_NAME		= "IUDX"
CA_NAME_LOWER   = CA_NAME.lower()  

IMAP_SERVER = 'imap.gmail.com'
SMTP_SERVER = 'smtp.gmail.com'

EMAIL_USER	= CA_NAME_LOWER + ".sub.ca"

AT_EMAIL_DOMAIN	= "@gmail.com"	# XXX change this
EMAIL_PASSWORD	= "password"	# XXX change this

SLEEP_TIME = 10 # seconds

UNPRIVILEGED_USER = "nobody"	# XXX may change this

############### Certificate details ##################

ORGANIZATION_NAME		= "MyOrganization"
ORGANIZATIONAL_UNIT_NAME	= "NA"
COUNTRY_NAME 			= "IN"
LOCALITY_NAME			= "MyCity"
POSTAL_CODE			= "123456" 
STATE_OR_PROVINCE_NAME  	= "MyState"
