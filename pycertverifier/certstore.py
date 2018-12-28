from .errors import DuplicateCertificateException, InvalidCertificateException

class CertStore(object):
    def __init__(self):
        self._store = dict()

    def add_cert(self, cert):
        if not cert.is_root():
            raise InvalidCertificateException("Only root certs allowed in cert store")
        subject = cert.cert_subject()
        if self._store.get(subject, None):
            raise DuplicateCertificateException("Certificate with subject: %s already in cert store" % subject)
        else:
            self._store[subject] = cert

    def get_cert(self, subject):
        return self._store.get(subject, None)

