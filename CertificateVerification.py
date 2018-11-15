import os
import base64
import binascii
import datetime
import traceback
import urllib.request
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtensionOID, NameOID, AuthorityInformationAccessOID

class DuplicateCertificateException(Exception):
    '''
    Raised when an existing certificate is being added to the Cert Store
    '''
    pass

class InvalidCertificateException(Exception):
    '''
    Raised when an invalid certificate is presented for a particular operation
    '''
    pass

class MyCertStore(object):
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


class MyCRL(object):
    def __init__(self, crl_data, data_type):
        self.crl = self._load_crl(crl_data, data_type)

    def _load_crl(self, crl_data, data_type):
        if data_type == "PEM":
            return x509.load_pem_x509_crl(crl_data, default_backend())
        elif data_type == "DER":
            return x509.load_der_x509_crl(crl_data, default_backend())
        return None

    def is_revoked(self, cert_serial):
       if self.crl and isinstance(cert_serial, int):
           return not (self.crl.get_revoked_certificate_by_serial_number(cert_serial) == None)
       return None

    def is_expired(self):
       if self.crl:
           d = datetime.datetime.now()
           return not ((d > crl.last_update) and (d < crl.next_update))
       return None

    def is_valid(self, pub_key):
       if self.crl:
           return self.crl.is_signature_valid(pub_key)
       return None

class MyCert(object):
    def __init__(self, cert_data, data_type, cert_store=None):
        print("#############################")
        self._cert = self._cert_load(cert_data, data_type)
        self._cert_store = cert_store
        self._subject = self._cert_subject()
        print("Cert subject: %s" % self._subject)
        self._issuer = self._cert_issuer()
        print("Cert issuer: %s" % self._issuer)
        self._fingerprint = self._cert_fingerprint()
        print("Cert fingerprint: %s" % self._fingerprint)
        self._pub_key = self._cert_pub_key()
        print("Cert public key: %s" % self._subject)
        self._subject_key_id = self._cert_subject_key_identifier()
        print("Cert SKI: %s" % self._subject_key_id)
        self._authority_key_id = self._cert_authority_key_identifier()
        print("Cert AKI: %s" % self._authority_key_id)
        self._root = self._cert_is_root()
        print("Cert root: %s" % self._root)
        self._aia = self._cert_aia()
        print("Cert aia: %s" % self._aia)
        self._ocsp = self._cert_ocsp()
        print("Cert ocsp: %s" % self._ocsp)
        self._crl = self._cert_crl()
        print("Cert crl: %s" % self._subject)
        self._revoked = self._cert_is_revoked()
        print("Cert revoked: %s" % self._revoked)
        print("#############################")

    def _cert_load(self, cert_data, data_type):
        if data_type == "PEM":
            return x509.load_pem_x509_certificate(cert_data, default_backend())
        elif data_type == "DER":
            return x509.load_der_x509_certificate(cert_data, default_backend())
        else:
            return None

    def _cert_subject(self):
        if self._cert:
            return ",".join([x.value for x in self._cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)])
        return None

    def _cert_issuer(self):
        if self._cert:
            return ",".join([x.value for x in self._cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)])

    def _cert_is_root(self):
        if self._cert:
            if len(self._cert.subject) != len(self._cert.issuer):
                return False
            else:
                for sub_attr in self._cert.subject:
                    iss_attrs = self._cert.issuer.get_attributes_for_oid(sub_attr.oid)
                    if not sub_attr.value in [iss_attr.value for iss_attr in iss_attrs]:
                        return False
                return True
        return None

    def _cert_pub_key(self):
        if self._cert:
            return self._cert.public_key()
        return None

    def _cert_fingerprint(self):
        if self._cert:
            return binascii.hexlify(self._cert.fingerprint(hashes.SHA256())).decode('utf-8')
        return None

    def __str__(self):
        return "subject=%s fingerprint=%s" % (self._subject, self._fingerprint)

    def _cert_subject_key_identifier(self):
        ski = None
        if self._cert:
            try:
                ski_ext = self._cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
                ski = binascii.hexlify(ski_ext.value.digest).decode('utf-8')
            except x509.ExtensionNotFound:
                print("Subject Key Identifier extension not found for cert: %s" % self)
        return ski

    def _cert_authority_key_identifier(self):
        aki = None
        if self._cert:
            try:
                aki_ext = self._cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
                aki = binascii.hexlify(aki_ext.value.key_identifier).decode('utf-8')
            except x509.ExtensionNotFound:
                print("Authority Key Identifier extension not found for cert: %s" % self)
        return aki

    def _cert_aia(self):
        aia = None
        if self._cert and not self._root:
            print("Getting AIA for %s" % self._subject)
            aia_ext = self._cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
            for ad in aia_ext.value:
                if ad.access_method == AuthorityInformationAccessOID.CA_ISSUERS:
                    aia_uri = ad.access_location.value
                    # print("Trying AIA uri: %s" % aia_uri)
                    aia_data = None
                    try:
                        print("Fetching AIA from %s" % aia_uri)
                        with urllib.request.urlopen(aia_uri) as response:
                            aia_data = response.read()
                            if aia_data:
                                print("Got data fpr uri: %s" % aia_uri)
                            else:
                                print("No data for uri: %s" % aia_uri)
                        if aia_data:
                            aia = MyCert(aia_data, "DER", self._cert_store)
                            print("aia._aia = %s" % aia._aia)
                            break
                    except Exception as e:
                        print("%s AIA uri %s download error: %s" % (self.__str__(), aia_uri, e))
                        traceback.print_exc()
            if aia == None:
                aia = self._cert_store.get_cert(self._issuer)
        return aia

    def _cert_ocsp(self):
        ocsp = None
        if self._cert and not self._root:
            ocsp_ext = self._cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
            for ad in ocsp_ext.value:
                if ad.access_method == AuthorityInformationAccessOID.OCSP:
                    ocsp_uri = ad.access_location.value
                    print("Trying OCSP uri: %s" % ocsp_uri)
                    ocsp_data = None
                    try:
                        ocsp_req_builder = x509.ocsp.OCSPRequestBuilder()
                        ocsp_req_builder = ocsp_req_builder.add_certificate(self._cert, self._aia.raw_cert(), hashes.SHA1())
                        ocsp_req = ocsp_req_builder.build()
                        ocsp_req = base64.b64encode(ocsp_req.public_bytes(serialization.Encoding.DER)).decode('utf-8')
                        ocsp_uri = ocsp_uri + '/' + ocsp_req
                        with urllib.request.urlopen(ocsp_uri) as response:
                            ocsp_data = response.read()
                        if ocsp_data:
                            ocsp = x509.ocsp.load_der_ocsp_response(ocsp_data)
                            break
                    except Exception as e:
                        print("%s OCSP uri %s error: %s" % (self.__str__(), ocsp_uri, e))
                        traceback.print_exc()
        return ocsp

    def _cert_crl(self):
        crl = None
        if self._cert and not self._root:
            crl_ext = self._cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
            for dp in crl_ext.value:
                if crl:
                    continue
                for crl_uri in dp.full_name:
                    crl_uri = crl_uri.value
                    crl_data = None
                    if crl_uri.endswith('.crl'):
                        try:
                            with urllib.request.urlopen(crl_uri) as response:
                                crl_data = response.read()
                            if crl_data:
                                crl = MyCRL(crl_data, "DER")
                                break
                                # if crl.is_valid(self._aia.cert_pub_key()):
                                #     break
                                # else:
                                #     print("%s CRL at uri %s cannot be verified with cert %s" % (self.__str__(), crl_uri, self.aia.__str__()))
                                #     crl = None
                        except Exception as e:
                            print("%s CRL uri %s error: %s" %(self.__str__(), crl_uri, e))
                            traceback.print_exc()
        return crl

    def is_expired(self):
        if self._cert:
            d = datetime.datetime.now()
            return not ((d > self._cert.not_valid_before) and (d < self._cert.not_valid_after))
        return None

    def cert_pub_key(self):
        return self._pub_key

    def _cert_is_revoked(self):
        if self._cert:
            if self._root:
                return False
            if self._crl:
                if self._aia:
                    if self._crl.is_valid(self._aia.cert_pub_key()):
                        return self._crl.is_revoked(self._cert.serial_number)
                    else:
                        print("%s CRL at uri %s cannot be verified with cert %s" % (self.__str__(), crl_uri, self.aia.__str__()))
        return None

    def is_root(self):
        return self._root;

    def is_revoked(self):
        return self._revoked;

    def ocsp_revoked(self):
        if self._cert:
            if self._ocsp:
                return self._ocsp.response_status
        return None

    def cert_is_valid(self):
        valid = True
        if self._cert:
            c = self
            while not c == None and valid:
                print("Checking cert: %s" % c)
                print("\troot: %s" % c.is_root())
                print("\texpired: %s" % c.is_expired())
                print("\trevoked: %s" % c.is_revoked())
                print("\tocsp response: %s" % c.ocsp_revoked())
                if c.is_expired():
                    valid = False
                if not c.is_root() and c.is_revoked() == True:
                    valid = False
                if not c.is_root() and c._aia == None:
                    valid = False
                c = c._aia
        else:
            valid = False
        return valid

    def raw_cert(self):
        return self._cert

    def cert_subject(self):
        return self._subject

