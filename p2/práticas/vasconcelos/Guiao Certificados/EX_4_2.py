from cryptography import x509
from cryptography.hazmat.backends import default_backend
import inspect
import os
import glob
from datetime import datetime
import sys

def verify_vality(cert):
	today=datetime.now()
	before=cert["not_valid_before"]
	after=cert["not_valid_after"]
	
	if before<= today<=after:
		return True
	else:
		return False

def load_certificate(filename,my_cert):
	with open(filename,"rb") as fr:
			my_text=fr.readlines()
			message=b''.join(my_text)
			#print(message)
	cert = x509.load_pem_x509_certificate(message, default_backend())
	my_cert[cert.subject]=[]
	my_atrributes={}
	for i in inspect.getmembers(cert):
	   
		if not i[0].startswith('_'):
			if not inspect.ismethod(i[1]):
				my_atrributes[i[0]]=i[1]
	my_cert[cert.subject]=my_atrributes

print("Loading user cert")
user_cert={}
load_certificate(sys.argv[1],user_cert)
print(f"User cert: {str(user_cert)}")

print("Loading intermidiate cert")
intermediate_cert={}
load_certificate(sys.argv[2],intermediate_cert)
print(f"Intermediate cert: {str(intermediate_cert)}")






      
my_cert={}
path = '/etc/ssl/certs/'
print("Loading roots")
for filename in glob.glob(os.path.join(path, '*.pem')):
	load_certificate(filename,my_cert)

'''#print(my_cert)
for cert in my_cert.values():
	verify_vality(cert)'''
	
