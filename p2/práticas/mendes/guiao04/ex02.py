import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime

roots = dict()
intermediate_certs = dict()
user_cert = dict()
chain=list()

def validate_revogation_status(cert):

    print(cert.extensions.get_extension_for_class(x509.CRLDistributionPoints))

def validate_cert(cert):
    today = datetime.now().timestamp()

    return cert.not_valid_before.timestamp() <= today <= cert.not_valid_after.timestamp()

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
    path = "/etc/ssl/certs"
    
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
    my_cert=load_cert("server.pem")
    if my_cert is not None:
        user_cert[my_cert.subject.rfc4514_string()] = my_cert
    validate_revogation_status(my_cert)

    print("Loading intermidiate cert")
    cert=load_cert("intermidiate.pem")
    if cert is not None:
        intermediate_certs[cert.subject.rfc4514_string()] = cert
    print(f"Intermediate cert: {str(intermediate_certs)}")

    build_issuers(chain,my_cert)
    print(f"Chain : {str(chain)}")

if __name__ == '__main__':
    main()
    







    