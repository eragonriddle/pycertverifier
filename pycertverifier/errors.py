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

class InvalidCertificateDataTypeException(Exception):
    '''
    Raised when an invalid certificate data type is presented for a particular operation
    '''
    pass

class InvalidCRLDataTypeException(Exception):
    '''
    Raised when an invalid crl data type is presented for a particular operation
    '''
    pass

class InvalidCRLException(Exception):
    '''
    Raised when an invalid CRL is used for verifying a certificate
    '''
    pass
