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

for slot in slots:
	#print(pkcs11.getTokenInfo(slot))

	all_attr = list(PyKCS11.CKA.keys())

	#Filter attributes
	all_attr = [e for e in all_attr if isinstance(e, int)]

	session = pkcs11.openSession(slot)
	for obj in session.findObjects():
		# Get object attributes
		attr = session.getAttributeValue(obj, all_attr)
		# Create dictionary with attributes
		attr = dict(zip(map(PyKCS11.CKA.get, all_attr), attr))
		
		print('Label: ', attr['CKA_LABEL'])
		if attr['CKA_CLASS']==1:
			load_certificate(bytes(attr['CKA_VALUE']))
		
