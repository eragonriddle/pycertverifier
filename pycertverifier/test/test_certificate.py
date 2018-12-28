import unittest

import pycertverifier

class TestCert(unittest.TestCase):
    
    def test_cert_load(self):
        self.assertRaises(pycertverifier.Cert('sdfsdf', 'PEM'), 'InvalidCertificateException')
