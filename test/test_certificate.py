import unittest

from pycertverifier.certificate import Cert
from pycertverifier.certstore import CertStore
from pycertverifier.errors import InvalidCertificateException, InvalidCertificateDataTypeException

class TestCert(unittest.TestCase):

    def setUp(self):
        self.leaf_cert_data = "-----BEGIN CERTIFICATE-----\nMIIHxzCCBq+gAwIBAgIIK284w3vFeHMwDQYJKoZIhvcNAQELBQAwVDELMAkGA1UEBhMCVVMxHjAcBgNVBAoTFUdvb2dsZSBUcnVzdCBTZXJ2aWNlczElMCMGA1UEAxMcR29vZ2xlIEludGVybmV0IEF1dGhvcml0eSBHMzAeFw0xODEwMDIwNzI5MDBaFw0xODEyMjUwNzI5MDBaMGYxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1Nb3VudGFpbiBWaWV3MRMwEQYDVQQKDApHb29nbGUgTExDMRUwEwYDVQQDDAwqLmdvb2dsZS5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATF/rmNsiifR0oFky0LhXnMlAmaec2W4RCu2AuJswLiMKYcrlOsU7lvMjrdz+gBlqpCIzTHosmdMjNFjAPEwHEjo4IFVDCCBVAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDgYDVR0PAQH/BAQDAgeAMIIEGQYDVR0RBIIEEDCCBAyCDCouZ29vZ2xlLmNvbYINKi5hbmRyb2lkLmNvbYIWKi5hcHBlbmdpbmUuZ29vZ2xlLmNvbYISKi5jbG91ZC5nb29nbGUuY29tggYqLmcuY2+CDiouZ2NwLmd2dDIuY29tggoqLmdncGh0LmNughYqLmdvb2dsZS1hbmFseXRpY3MuY29tggsqLmdvb2dsZS5jYYILKi5nb29nbGUuY2yCDiouZ29vZ2xlLmNvLmlugg4qLmdvb2dsZS5jby5qcIIOKi5nb29nbGUuY28udWuCDyouZ29vZ2xlLmNvbS5hcoIPKi5nb29nbGUuY29tLmF1gg8qLmdvb2dsZS5jb20uYnKCDyouZ29vZ2xlLmNvbS5jb4IPKi5nb29nbGUuY29tLm14gg8qLmdvb2dsZS5jb20udHKCDyouZ29vZ2xlLmNvbS52boILKi5nb29nbGUuZGWCCyouZ29vZ2xlLmVzggsqLmdvb2dsZS5mcoILKi5nb29nbGUuaHWCCyouZ29vZ2xlLml0ggsqLmdvb2dsZS5ubIILKi5nb29nbGUucGyCCyouZ29vZ2xlLnB0ghIqLmdvb2dsZWFkYXBpcy5jb22CDyouZ29vZ2xlYXBpcy5jboIUKi5nb29nbGVjb21tZXJjZS5jb22CESouZ29vZ2xldmlkZW8uY29tggwqLmdzdGF0aWMuY26CDSouZ3N0YXRpYy5jb22CEiouZ3N0YXRpY2NuYXBwcy5jboIKKi5ndnQxLmNvbYIKKi5ndnQyLmNvbYIUKi5tZXRyaWMuZ3N0YXRpYy5jb22CDCoudXJjaGluLmNvbYIQKi51cmwuZ29vZ2xlLmNvbYIWKi55b3V0dWJlLW5vY29va2llLmNvbYINKi55b3V0dWJlLmNvbYIWKi55b3V0dWJlZWR1Y2F0aW9uLmNvbYIRKi55b3V0dWJla2lkcy5jb22CByoueXQuYmWCCyoueXRpbWcuY29tghphbmRyb2lkLmNsaWVudHMuZ29vZ2xlLmNvbYILYW5kcm9pZC5jb22CG2RldmVsb3Blci5hbmRyb2lkLmdvb2dsZS5jboIcZGV2ZWxvcGVycy5hbmRyb2lkLmdvb2dsZS5jboIEZy5jb4IIZ2dwaHQuY26CBmdvby5nbIIUZ29vZ2xlLWFuYWx5dGljcy5jb22CCmdvb2dsZS5jb22CEmdvb2dsZWNvbW1lcmNlLmNvbYIYc291cmNlLmFuZHJvaWQuZ29vZ2xlLmNuggp1cmNoaW4uY29tggp3d3cuZ29vLmdsggh5b3V0dS5iZYILeW91dHViZS5jb22CFHlvdXR1YmVlZHVjYXRpb24uY29tgg95b3V0dWJla2lkcy5jb22CBXl0LmJlMGgGCCsGAQUFBwEBBFwwWjAtBggrBgEFBQcwAoYhaHR0cDovL3BraS5nb29nL2dzcjIvR1RTR0lBRzMuY3J0MCkGCCsGAQUFBzABhh1odHRwOi8vb2NzcC5wa2kuZ29vZy9HVFNHSUFHMzAdBgNVHQ4EFgQUMSRXCWF76N8rFveDQsxflVh2PO4wDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBR3wrhQmmd2drEtwobQg6B+pn66SzAhBgNVHSAEGjAYMAwGCisGAQQB1nkCBQMwCAYGZ4EMAQICMDEGA1UdHwQqMCgwJqAkoCKGIGh0dHA6Ly9jcmwucGtpLmdvb2cvR1RTR0lBRzMuY3JsMA0GCSqGSIb3DQEBCwUAA4IBAQBU/YOOkf8+wI47qrWwoRR4seHbxKQPVl2cNz1T+DAtB9gCAVxr/ceSLUoZE6biY870PeQhU5Z4RVTWhvAQ+8pZSNK6pkP5ZIq5wNH5/OofY7fDxFK5nqt2LQt5P4YyWA3kyWtqatGKSf1WIzffOOwp95XBV+1AtMgqEK5qxM5v/74+oufKAtgDL+25EDYVG/It7YiFabq/mJIT70vtz6f6O+o+IM6Q9cN+M0VDV0LSmBC3zJ+/0pstnOR3BBSgD8yDChqi0rg5u/1Fu0SQoqozf1s9kFfq0w6rM5dYKK8ImtJO9UXEW7DZ5qu5ext4BPbPUyZhmEI2MgWTxg4GYXxC\n-----END CERTIFICATE-----"
        self.root_cert_data = "-----BEGIN CERTIFICATE-----\nMIIDujCCAqKgAwIBAgILBAAAAAABD4Ym5g0wDQYJKoZIhvcNAQEFBQAwTDEgMB4GA1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjIxEzARBgNVBAoTCkdsb2JhbFNpZ24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMDYxMjE1MDgwMDAwWhcNMjExMjE1MDgwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMjETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKbPJA6+Lm8omUVCxKs+IVSbC9N/hHD6ErPLv4dfxn+G07IwXNb9rfF73OX4YJYJkhD10FPe+3t+c4isUoh7SqbKSaZeqKeMWhG8eoLrvozps6yWJQeXSpkqBy+0Hne/ig+1AnwblrjFuTosvNYSuetZfeLQBoZfXklqtTleiDTsvHgMCJiEbKjNS7SgfQx5TfC4LcshytVsW33hoCmEofnTlEnLJGKRILzdC9XZzPnqJworc5HGnRusyMvo4KD0L5CLTfuwNhv2GXqF4G3yYROIXJ/gkwpRl4pazq+r1feqCapgvdzZX99yqWATXgAByUr6P6TqBwMhAo6CygPCm48CAwEAAaOBnDCBmTAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUm+IHV2ccHsBqBt5ZtJot39wZhi4wNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL2NybC5nbG9iYWxzaWduLm5ldC9yb290LXIyLmNybDAfBgNVHSMEGDAWgBSb4gdXZxwewGoG3lm0mi3f3BmGLjANBgkqhkiG9w0BAQUFAAOCAQEAmYFThxxol4aR7OBKuEQLq4GsJ0/WwbgcQ3izDJr86iw8bmEbTUsp9Z8FHSbBuOmDAGJFtqkIk7mpM0sYmsL4h4hO291xNBrBVNpGP+DTKqttVCL1OmLNIG+6KYnX3ZHu01yiPqFbQfXf5WRDLenVOavSot+3i9DAgBkcRcAtjOj4LaR0VknFBbVPFd5uRHg5h6h+u/N5GJG79G+dwfCMNYxdAfvDbbnvRG15RjF+Cv6pgsH/76tuIMRQyV+dTZsXjAzlAcmgQWpzU/qlULRuJQ/7TBj0/VLZjmmx6BEP3ojY+x1J96relc8geMJgEtslQIxq/H5COEBkEveegeGTLg==\n-----END CERTIFICATE-----"
        self.root_cert = Cert(self.root_cert_data.encode('utf8'), 'PEM')
        self.cert_store = CertStore()
        self.cert_store.add_cert(self.root_cert)
        self.leaf_cert = Cert(self.leaf_cert_data.encode('utf8'), 'PEM', self.cert_store)
   
    def test_cert_load(self):
        with self.assertRaises(InvalidCertificateException):
            Cert('blah', 'PEM')

        with self.assertRaises(InvalidCertificateDataTypeException):
                Cert(self.leaf_cert_data.encode('utf8'), 'PEME')

    def test_cert_subject(self):
        self.assertEqual('*.google.com', self.leaf_cert.cert_subject())

    def test_ocsp_revoked(self):
        self.assertFalse(self.leaf_cert.ocsp_revoked())

    def test_is_revoked(self):
        self.assertFalse(self.leaf_cert.is_revoked())

    def test_is_expired(self):
        self.assertTrue(self.leaf_cert.is_expired())

    def test_cert_fingerprint(self):
        self.assertEqual('754f8d0bf5b06776c6ebdabeb019840eb16b0a7b53bd11973e25e698761e426d', self.leaf_cert.cert_fingerprint())

    def test_cert_is_valid(self):
        self.assertFalse(self.leaf_cert.cert_is_valid())

    def test_cert_is_root(self):
        self.assertTrue(self.root_cert.is_root())
        self.assertFalse(self.leaf_cert.is_root())

    def tearDown(self):
        self.leaf_cert = None
        self.cert_store = None
        self.root_cert = None
