import os
import wget
from cryptography import x509
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.x509 import ocsp
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from datetime import datetime
from cryptography.x509.oid import NameOID
import requests
import json

from cryptography.hazmat.primitives import serialization, hashes



roots = dict()
intermediate_certs = dict()
user_cert = dict()
chain=list()

def validate_chain(cert_to_check,issuer_cert):
    cert_to_check_signature=cert_to_check.signature
    issuer_public_key=issuer_cert.public_key()
    
    # TODO check if host has the same name I think
    builder = ocsp.OCSPRequestBuilder()
    # SHA1 is in this example because RFC 5019 mandates its use.
    builder = builder.add_certificate(cert_to_check, issuer_cert, SHA1())
    req = builder.build()

    '''for j in cert_to_check.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value:
            if j.access_method.dotted_string == "1.3.6.1.5.5.7.48.1": 
                rev_list=None

                #Downloading list
                der=req.public_bytes(serialization.Encoding.DER)

                ocsp_link=j.access_location.value
                r=requests.post(ocsp_link,data=der)

                ocsp_resp = ocsp.load_der_ocsp_response(r.content)
                print(ocsp_resp.certificate_status)'''



                

    
    



    
    print(cert_to_check.extensions.get_extension_for_class(x509.KeyUsage).value)


    if (get_issuer_common_name(cert_to_check)!=get_common_name(issuer_cert)):
        print(get_issuer_common_name(cert_to_check))
        print(get_common_name(issuer_cert))
        return False 
        

    try:
        issuer_public_key.verify(cert_to_check_signature,cert_to_check.tbs_certificate_bytes,padding.PKCS1v15(),cert_to_check.signature_hash_algorithm)
    except:
        print("Failed to verify signature.")
        return False
    
    return True

def get_issuer_common_name(cert):
    try:
        names = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        return names[0].value
    except x509.ExtensionNotFound:
        return None


def get_public_key_from_cert(self):

def get_common_name(self,cert):
    try:
        names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        return names[0].value
    except x509.ExtensionNotFound:
        return None


def validate_revogation_status(cert):

    # check certificate revogation list
    # TODO: add more types of dist points
    print(cert.extensions)
    try:
        for j in cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value:
            if j.access_method.dotted_string == "1.3.6.1.5.5.7.48.1": 
                rev_list=None

                #Downloading list
                print(j.access_location.value)
                file_name=wget.download(j.access_location.value)

                #Load ocsp response
                with open(file_name, "rb") as pem_file:
                    pem_data = pem_file.read()
                ocsp_resp = ocsp.load_der_ocsp_response(pem_data)

                print(ocsp_resp.response_status)
    except:
        print("OCSP not available.")



    try:
        for i in cert.extensions.get_extension_for_class(x509.CRLDistributionPoints).value:
            for b in i.full_name:
                file_name=b.value.split('/')[-1]
                rev_list=None
                #Downloading list
                print(wget.download(b.value))

                #read revocation list
                try:
                    rev_list=load_cert_revocation_list(file_name,"pem")
                except:
                    print("Not pem.")
                try:
                    rev_list=load_cert_revocation_list(file_name,"der")
                except:
                    print("Not der.")
                print(rev_list)
                if rev_list is None:
                    return False
                
                return cert.serial_number in [l.serial_number for l in rev_list]
    except:
        print("CRL not available.")
        return False

def validate_cert(cert):
    today = datetime.now().timestamp()

    return cert.not_valid_before.timestamp() <= today <= cert.not_valid_after.timestamp()

def load_cert_revocation_list(filename,file_type):
    with open(filename, "rb") as pem_file:
        pem_data = pem_file.read()
        if file_type=="der":
            cert = x509.load_der_x509_crl(pem_data, default_backend())
        elif file_type=="pem":
            cert = x509.load_pem_x509_crl(pem_data, default_backend())

    return cert

    

def load_cert(filename):
    with open(filename, "rb") as pem_file:
        pem_data = pem_file.read()
        cert = x509.load_pem_x509_certificate(pem_data, default_backend())

    if validate_cert(cert):
        return cert
    
def build_issuers(chain, cert):
        chain.append(cert)

        issuer = cert.issuer.rfc4514_string()
        subject = cert.subject.rfc4514_string()
        print("----")
        print(f"Issuer : {issuer}")
        print(f"Subject : {subject}")
        print("----")

        if issuer == subject and subject in roots:
            return 
        
        if issuer in intermediate_certs:
            return build_issuers(chain, intermediate_certs[issuer])
        
        if issuer in roots:
            return build_issuers(chain, roots[issuer])
        
        return

def main():
    path = "/home/joao/Documents/Documents/3º_ano/SIO/Projeto SIO/secure-communication/p2/server_roots"
    
    print(f"Scanning {path}...")
    folder = os.scandir(path)
    
    invalid = 0
    print(f"Loading certificates...")
    for entry in folder:
        if entry.is_file() and '.pem' in entry.name:
            cert = load_cert(path + "/" + entry.name)
            if cert is not None:
                roots[cert.subject.rfc4514_string()] = cert
            else: 
                invalid += 1
                
        
    print(f"Loaded {len(roots)} root valid certificates, {invalid} rejected!")
    
    print("Loading user cert")
    my_cert=load_cert("/home/joao/Documents/Documents/3º_ano/SIO/Projeto SIO/secure-communication/p2/server_cert/secure_server.pem")
    if my_cert is not None:
        user_cert[my_cert.subject.rfc4514_string()] = my_cert

        
    validate_revogation_status(cert)
    validate_chain(my_cert,cert)

    print("Loading intermidiate cert")
    cert=load_cert("intermidiate.pem")
    '''
    if cert is not None:
        intermediate_certs[cert.subject.rfc4514_string()] = cert
    print(f"Intermediate cert: {str(intermediate_certs)}")

    build_issuers(chain,my_cert)
    print(f"Chain : {str(chain)}")'''

if __name__ == '__main__':
    main()
    







    