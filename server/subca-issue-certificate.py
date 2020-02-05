# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4

'''
/*
 * Copyright (c) 2019
 * Arun Babu {arun <dot> hbni <at> gmail}
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
'''

import re
import os
import pwd
import sys
import ssl
import time
import stat
import imaplib
import smtplib
import getpass
import requests
import tempfile
import datetime
import subprocess

import urllib3
# for telegram
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import email
from email import message_from_string 
from email.generator import Generator	# pre-load this module for chroot
from email.parser import * 
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase

from cryptography import x509
from cryptography.x509.oid import NameOID

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.primitives.serialization import load_pem_private_key

from conf.common import *
from conf.subca import *

from employee_db import *

openbsd = None
try:
    import openbsd
except:
    print "WARNING: openbsd package not found !!!"
    pass

f = open("telegram.apikey", "r")
telegram_apikey = f.read().strip()
f.close()

f = open("telegram.chatid", "r")
telegram_chatid = f.read().strip()
f.close()

def send_telegram(message):
        message = "[ rbccps-sub-CA ] : " + time.ctime()+ ' ' + message 
        try:
            # use telegram.org if telegram is not blocked
            requests.get("https://149.154.167.220/bot" + telegram_apikey +"/sendMessage?chat_id="+telegram_chatid+"&text="+message,verify=False)
        except:
            print "COULD not send message to telegram"

if re.search(r'\s',CA_NAME):
	print "CA name cannot contain spaces"
	sys.exit(-1)

if os.geteuid() != 0:
	print "\nWarning: As you are not root, 'chroot' and 'privileges droping' ",
	print "features will NOT be available !\n"

# get the CA's certificate
f = open("../cert/sub-ca.crt", "r")
ca_cert_pem = f.read().strip()
f.close()

f = open("../cert/sub-ca.private.key")
ca_private_key_pem = f.read().strip()
f.close()

print ""

ca_cert_password = None
if ca_private_key_pem.startswith("-----BEGIN ENCRYPTED "):
	ca_cert_password = getpass.getpass(prompt='---> Enter password for the sub-CA\'s private key : ', stream=None)

ca_cert 	= x509.load_pem_x509_certificate(ca_cert_pem, default_backend())
ca_private_key 	= load_pem_private_key(ca_private_key_pem,password=ca_cert_password,backend=default_backend())

print "\n===> Logging in ..."

m = imaplib.IMAP4_SSL(IMAP_SERVER, '993')
m.login(EMAIL_USER + AT_EMAIL_DOMAIN, EMAIL_PASSWORD)

print "===> Logged in  ...\n"

if os.geteuid() == 0:
#{
	ca_uid = pwd.getpwnam(UNPRIVILEGED_USER).pw_uid
	ca_gid = pwd.getpwnam(UNPRIVILEGED_USER).pw_gid

	os.chmod("./jail",stat.S_IRUSR | stat.S_IXUSR | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH )

	# ------------ pre-load some modules for chroot --------------

	dummy = x509.CertificateSigningRequestBuilder().subject_name(
		x509.Name([
			x509.NameAttribute(NameOID.COUNTRY_NAME, u"IN")
		])
	).sign (ca_private_key,hashes.SHA256(), default_backend())

	# ------------ end pre-load some modules for chroot --------------

	try:
		os.chroot("./jail")
		os.chdir("/")
	except Exception as e:
		print "*** Failed to chroot",e
		sys.exit(-1)	
	
	try:
		os.setgid(ca_gid)
	except Exception as e:
		print "*** Failed to setgid",e
		sys.exit(-1)	

	try:
		os.setuid(ca_uid)
	except Exception as e:
		print "*** Failed to setuid",e
		sys.exit(-1)	
#}

# TODO: This should go into a DB instead
cert_issued_time = {}

invalid_email_id_chars = [
	"/",
	"=",
	",",
	";",
	":",
	"\\",
]

if openbsd:
    openbsd.unveil("/","")
    openbsd.pledge("stdio rpath inet dns")

while True:
#{
	try:
		m.select('INBOX')
	except:
		m.logout()
		m = imaplib.IMAP4_SSL(IMAP_SERVER, '993')
		m.login(EMAIL_USER + AT_EMAIL_DOMAIN, EMAIL_PASSWORD)
		continue

	print "[ " + time.ctime()+' ] Checking for new emails ...', 

	try:
		unread = m.search(None, 'UnSeen')
	except:
		m.logout()
		m = imaplib.IMAP4_SSL(IMAP_SERVER, '993')
		m.login(EMAIL_USER + AT_EMAIL_DOMAIN, EMAIL_PASSWORD)
		continue

	unread_ids = (unread[1][0].split())

	if len(unread_ids) > 0:
		print ' got', len(unread_ids), 'new email(s)'
	else:
		print " no unread emails"

	for x in unread_ids: 
	#{
		_, data = m.fetch(x,'(RFC822)')
		part  = data[0]

		if not isinstance(part,tuple):
			continue

                m.store(x, '+FLAGS', '\Seen')

		print "\n-------------------", x ,"----------------------------"

		msg = email.message_from_string(part[1])

		# reject if mail does not contain attachments
		if msg.get_content_maintype() != 'multipart':
			# reply_with_error (from_email)
			print "*** Got a mail without attachments ..."
			continue	

		# reject if mail does not have a valid subject 
		subject	= msg['subject'].strip()
		if not subject.lower().startswith('certificate request'):
			print "*** Got a mail with invalid subject ..."
			continue	

		_from = msg['from'].strip().replace("<"," ")
		_from = _from.strip().replace(">","").split(" ")

		# hopefully last one is the email-id
		from_email = _from[-1].strip() 

		print "From",from_email

		if from_email.count("@") != 1:
			print "*** Doesn't look like a valid email : <" + from_email +">"
			continue

		# shortest email can be "a@b"
		if len(from_email) < 3:
			print "*** Email id: <" + from_email +">", "is too small ..."
			continue

		if not from_email.endswith(AT_EMAIL_DOMAIN):
			print "*** Email id is not valid ..."
			continue

                # reject if email id or domain contains strange chars !
		contains_invalid_chars = False
		for inv in invalid_email_id_chars:
                	if from_email.find(inv) >= 0:
				contains_invalid_chars = True
				break

                # reject if email id or domain contains spaces
                if re.search(r'\s',from_email):
                        contains_invalid_chars = True

		if contains_invalid_chars:
			print "*** Email id: <" + from_email +">", "contains invalid chars ..."
			continue

		#########################################################################

		ar = msg['Authentication-Results']

		spf_pass 	= False 
		dkim_pass 	= False 

		if ar:
			if ar.find("spf = pass ") > 0 :
				spf_pass = True 

			if ar.find("dkim = pass ") > 0:
				dkim_pass = True

		# is_trusted_email = spf_pass and dkim_pass # required ?
		is_trusted_email = True 

		if not is_trusted_email:
			print "*** Not a trusted email from ...", from_email
			continue 

		#########################################################################
	
		is_data_officer		= False
		is_resource_server	= False

		# reject if a certificate was already issued less than a day ago
		if from_email in cert_issued_time:
		#{
			issued_time = time.time() - cert_issued_time[from_email] 

			if issued_time < (24*60*60): 
				print "*** Already issued a certificate for ",\
					from_email,issued_time, "seconds back"
				#continue	
		#}

		payload = msg.get_payload()

		csr_data = None

		# check attachments
		for attachment in payload:
		#{
			file_name = attachment.get_filename()
			if file_name and file_name.endswith(".pem"):
				csr_data = attachment \
						.get_payload(decode=True) \
						.strip() 
				break
		#}

		# reject if there was no .pem files as attachment
		if not csr_data:
			#reply_with_error (from_email)
			print "*** No CSR found in email from ",from_email
			continue	
		else:
			if not csr_data.startswith("-----BEGIN CERTIFICATE REQUEST-----"):
				print "*** Email sent by",from_email,"contains invalid CSR !"
				continue

			if not csr_data.endswith("-----END CERTIFICATE REQUEST-----"):
				print "*** Email sent by",from_email,"contains invalid CSR !"
				continue

		try:
			csr = x509.load_pem_x509_csr(csr_data, default_backend())
		except Exception as e:
			print "*** Email sent by",from_email,"does not have a valid CSR !. Exception: ",e
			continue
			
		if not csr.is_signature_valid:
			print "*** Email sent by",from_email,"does not have a valid signature !"
			continue

		print "=== Request for certificate: ",from_email

		public_key = csr.public_key().public_bytes(PEM,PKCS1).strip()

		if not public_key.startswith("-----BEGIN "): 
			print "*** Public key BEGINS with :"+public_key
			continue

		if not public_key.endswith(" PUBLIC KEY-----"):
			print "*** Public key ENDS with "+public_key+":"
			continue

		print "=== Request from ",from_email,"looks ok "
		print "=== spf_pass = ",spf_pass," dkim_pass = ",dkim_pass


		if from_email not in EMPLOYEE_DB:
			print "*** Employee "+from_email+" is not eligible to get IUDX certificate"
			continue

		first_name 	= EMPLOYEE_DB [from_email][0]
		last_name	= EMPLOYEE_DB [from_email][1]
		title 		= EMPLOYEE_DB [from_email][2]
		cert_class	= EMPLOYEE_DB [from_email][3]
		valid_days      = EMPLOYEE_DB [from_email][4]

		if not is_trusted_email:
                        print "*** untrusted email :"+from_email
		        continue

		now 		= datetime.datetime.now() 
		now             = now - datetime.timedelta(days=1)
		valid_till      = now + datetime.timedelta(days=valid_days + 1)

		cn = title + " at " + from_email.split("@")[1] 

		l = subject.lower()
		if l.startswith("certificate request rs "):
		#
			try:
				resource_server_name = subject.split(" ")[3].lower()

                		if not bool(re.match('^[-\.a-zA-Z0-9]+$', resource_server_name)):
					print "*** invalid resource server name from :"+from_email
					continue

				if len(resource_server_name) > 256:
					print "*** resource server name too long by :"+from_email
					continue

				is_resource_server = True 

		                cert_class = "1"
				cn = resource_server_name # Change CN for resource server

				valid_till = now + datetime.timedelta(days=366)

			except Exception as e:
				print "*** something went wrong :"+from_email,e
				continue
		#


		cb = x509.CertificateBuilder()				\
			.subject_name(					\
				x509.Name([				\
					x509.NameAttribute(NameOID.COMMON_NAME, 		unicode(cn,'utf-8')), \
					x509.NameAttribute(NameOID.EMAIL_ADDRESS, 		unicode(from_email,'utf-8')), \
					x509.NameAttribute(NameOID.ORGANIZATION_NAME, 		unicode(ORGANIZATION_NAME,'utf-8')), \
					x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, 	unicode(ORGANIZATIONAL_UNIT_NAME,'utf-8')), \
					x509.NameAttribute(NameOID.COUNTRY_NAME, 		unicode(COUNTRY_NAME,'utf-8')), \
					x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, 	unicode(STATE_OR_PROVINCE_NAME,'utf-8')), \
					x509.NameAttribute(NameOID.GIVEN_NAME, 			unicode(first_name,'utf-8')), \
					x509.NameAttribute(NameOID.SURNAME, 			unicode(last_name,'utf-8')), \
					x509.NameAttribute(NameOID.TITLE, 			unicode(title,'utf-8')), \
					x509.NameAttribute(x509.CertificatePoliciesOID.CPS_USER_NOTICE,u"class:"+cert_class)\
				])					\
			)						\
			.issuer_name(ca_cert.subject)			\
			.public_key(csr.public_key())			\
			.serial_number(x509.random_serial_number())	\
			.not_valid_before(now)				\
			.not_valid_after(valid_till)

		cert = cb.sign(ca_private_key, hashes.SHA256(), default_backend())

		certificate = cert.public_bytes(PEM).strip()

		if not certificate.startswith("-----BEGIN CERTIFICATE-----"):
			print "*** [BEGIN] invalid certificate generated :"+certificate
			continue

		if not certificate.endswith("-----END CERTIFICATE-----"):
			print "*** [END] invalid certificate generated "+certificate+":"
			continue

		certificate = certificate + "\n" + ca_cert_pem

		reply = MIMEMultipart()

                domain = AT_EMAIL_DOMAIN.split("@")[1]

		reply['Subject'] 	= 'Re: ' + subject
		reply['From'] 		= CA_NAME + " sub-Certificate Authority at " + domain  + " <"+ EMAIL_USER + AT_EMAIL_DOMAIN + ">" 
		reply['To'] 		= from_email 

                attachment_name = from_email+'-class-'+ str(cert_class) + '-certificate.pem'

		reply_message   = "Dear " + CA_NAME + " user,\n\n"							                \
                                + "We have processed your request for a class-" + str(cert_class) + " digital certificate for \""       \
                                + from_email +"\"\nwith the following public key:\n\n"					                \
                                + public_key +"\n\nPlease find your digital ceritificate attached.\n\n"                                 \
                                + "You may convert the certificate to P12 format to be used in a web-browser by running the command:\n" \
                                + "$ openssl pkcs12 -inkey private-key.pem -in "+ attachment_name  +" -export -out certificate.p12\n"\
                                + "\nRegards,\n"\
                                + CA_NAME + " sub-Certificate Authority at " + domain 

		reply.attach (MIMEText(reply_message))

		reply_attachment = MIMEBase('application',"application/x-x509-user-cert")
		reply_attachment.set_payload(certificate)
		reply_attachment.add_header('Content-Disposition', 'attachment; filename="' + attachment_name + '"')
		reply.attach (reply_attachment)

		try:
			server = smtplib.SMTP_SSL(SMTP_SERVER, 465)
			server.ehlo()
			server.login(EMAIL_USER + AT_EMAIL_DOMAIN, EMAIL_PASSWORD)
			server.sendmail(EMAIL_USER + AT_EMAIL_DOMAIN, from_email, reply.as_string())
			server.close()

			cert_issued_time[from_email] = time.time()

			print '=== Certificate sent to:',from_email

		except Exception as e: 
			print '=== Something went wrong while sending certificate ... :', e

                if cert_class == 1:
                       send_telegram("class-" + str(cert_class) + " certificate issued to " + from_email + " for " + cn) 
                else:
                       send_telegram("class-" + str(cert_class) + " certificate issued to " + from_email)
			
		print "-------------------------------------------------\n"
	#}

	time.sleep(SLEEP_TIME)
#}
