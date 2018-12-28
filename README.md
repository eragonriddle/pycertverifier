# pycertverifier
A python module for x509 certificates for chain validation and revocation checking

# Installation
python setup.py sdist bdist_wheel  
pip install dist/pycertverifier-0.0.1-py3-none-any.whl  

# Usage
from pycertverifier.certificate import Cert  
from pycertverifier.certstore import CertStore  

root_cert_path = ''  
test_cert_path = ''  

with open(root_cert_path, 'rb') as rc:  
    root_cert_data = rc.read()  
root_cert = Cert(root_cert_data, 'PEM')  
cert_store = CertStore()  
cert_store.add_cert(root_cert)  
    
with open(test_cert_path, 'rb') as rc:  
    test_cert_data = rc.read()  
test_cert = Cert(test_cert_data, 'PEM', cert_store)  

print("Certificate is valid = %s" % test_cert.cert_is_valid())  
print("Certificate subject = %s" % test_cert.cert_subject())  
print("Certificate thumbprint = %s" % test_cert.fingerprint())  
