import PyKCS11
import binascii
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import inspect
import os
import glob
from datetime import datetime
import sys


def load_certificate(my_cert):
	
	cert = x509.load_der_x509_certificate(my_cert, default_backend())
	print("---CERTIFICATE---")
	print(f"Subject: {cert.subject}")
	print(f"Issuer: {cert.issuer}")


lib ='/usr/local/lib/libpteidpkcs11.so'

pkcs11 = PyKCS11.PyKCS11Lib()
pkcs11.load(lib)

slots = pkcs11.getSlotList()
filename='msg.txt'

for slot in slots:
	#print(pkcs11.getTokenInfo(slot))

	all_attr = list(PyKCS11.CKA.keys())

	#Filter attributes
	all_attr = [e for e in all_attr if isinstance(e, int)]

	session = pkcs11.openSession(slot)
	
	private_key = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),(PyKCS11.CKA_LABEL,'CITIZEN AUTHENTICATION KEY')])[0]

	mechanism = PyKCS11.Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS, None)
	
	'''with open(filename,"rb") as fr:
			my_text=fr.readlines()
			text=b''.join(my_text)
	print(text)'''
	text = b'text to sign'

	signature = bytes(session.sign(private_key, text, mechanism))
