import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend

from .errors import InvalidCRLDataTypeException

class CRL(object):
    def __init__(self, crl_data, data_type):
        self.crl = self._load_crl(crl_data, data_type)

    def _load_crl(self, crl_data, data_type):
        if data_type == "PEM":
            return x509.load_pem_x509_crl(crl_data, default_backend())
        elif data_type == "DER":
            return x509.load_der_x509_crl(crl_data, default_backend())
        else:
            raise InvalidCRLDataTypeException('crl data type %s not recognized' % data_type)
        return None

    def is_revoked(self, cert_serial):
       if self.crl and isinstance(cert_serial, int):
           return not (self.crl.get_revoked_certificate_by_serial_number(cert_serial) == None)
       return None

    def is_expired(self):
        d = datetime.datetime.now()
        return not ((d > self.crl.last_update) and (d < self.crl.next_update))

    def is_valid(self, pub_key):
        return self.crl.is_signature_valid(pub_key)
