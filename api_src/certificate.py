import datetime
import sys

from asn1crypto import cms
from dateutil.parser import parse
from pypdf import PdfReader
import base64
import io

# from: https://stackoverflow.com/questions/72556172/how-to-locate-digital-signatures-in-pdf-files-with-python/77515811#77515811


class AttrClass:
    """Abstract helper class"""

    def __init__(self, data, cls_name=None):
        self._data = data
        self._cls_name = cls_name

    def __getattr__(self, name):
        try:
            value = self._data[name]
        except KeyError:
            value = None
        else:
            if isinstance(value, dict):
                return AttrClass(value, cls_name=name.capitalize() or self._cls_name)
        return value

    def __values_for_str__(self):
        """Values to show for "str" and "repr" methods"""
        return [
            (k, v) for k, v in self._data.items()
            if isinstance(v, (str, int, datetime.datetime))
        ]

    def __str__(self):
        """String representation of object"""
        values = ", ".join([
            f"{k}={v}" for k, v in self.__values_for_str__()
        ])
        return f"{self._cls_name or self.__class__.__name__}({values})"

    def __repr__(self):
        return f"<{self}>"


class Signature(AttrClass):
    """Signature helper class

    Attributes:
        type (str): 'timestamp' or 'signature'
        signing_time (datetime, datetime): when user has signed
            (user HW's clock)
        signer_name (str): the signer's common name
        signer_contact_info (str, None): the signer's email / contact info
        signer_location (str, None): the signer's location
        signature_type (str): ETSI.cades.detached, adbe.pkcs7.detached, ...
        certificate (Certificate): the signers certificate
        digest_algorithm (str): the digest algorithm used
        message_digest (bytes): the digest
        signature_algorithm (str): the signature algorithm used
        signature_bytes (bytest): the raw signature
    """

    @property
    def signer_name(self):
        return (
            self._data.get('signer_name') or
            getattr(self.certificate.subject, 'common_name', '')
        )


class Subject(AttrClass):
    """Certificate subject helper class

    Attributes:
        common_name (str): the subject's common name
        given_name (str): the subject's first name
        surname (str): the subject's surname
        serial_number (str): subject's identifier (may not exist)
        country (str): subject's country
    """
    pass


class Certificate(AttrClass):
    """Signer's certificate helper class

    Attributes:
        version (str): v3 (= X509v3)
        serial_number (int): the certificate's serial number
        subject (object): signer's subject details
        issuer (object): certificate issuer's details
        signature (object): certificate signature
        extensions (list[OrderedDict]): certificate extensions
        validity (object): validity (not_before, not_after)
        subject_public_key_info (object): public key info
        issuer_unique_id (object, None): issuer unique id
        subject_uniqiue_id (object, None): subject unique id
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.subject = Subject(self._data['subject'])

    def __values_for_str__(self):
        return (
            super().__values_for_str__() +
            [('common_name', self.subject.common_name)]
        )


def parse_pkcs7_signatures(signature_data: bytes):
    """Parse a PKCS7 / CMS / CADES signature"""
    content_info = cms.ContentInfo.load(signature_data).native
    if content_info['content_type'] != 'signed_data':
        return None
    content = content_info['content']
    certificates = content['certificates']
    # each PKCS7 / CMS / CADES could have several signatures
    signer_infos = content['signer_infos']
    for signer_info in signer_infos:
        # the sid key should point to the certificates collection
        sid = signer_info['sid']
        digest_algorithm = signer_info['digest_algorithm']['algorithm']
        signature_algorithm = signer_info['signature_algorithm']['algorithm']
        signature_bytes = signer_info['signature']
        # signed attributes is a list of key, value pairs
        # oversimplification: normally we have no repeated attributes
        signed_attrs = {
            sa['type']: sa['values'][0] for sa in signer_info['signed_attrs']}
        # find matching certificate, only for issuer / serial number
        for cert in certificates:
            cert = cert['tbs_certificate']
            if (
                sid['serial_number'] == cert['serial_number'] and
                sid['issuer'] == cert['issuer']
            ):
                break
        else:
            raise RuntimeError(
                f"Couldn't find certificate in certificates collection: {sid}")
        yield dict(
            sid=sid,
            certificate=Certificate(cert),
            digest_algorithm=digest_algorithm,
            signature_algorithm=signature_algorithm,
            signature_bytes=signature_bytes,
            signer_info=signer_info,
            **signed_attrs,
        )


def get_pdf_signatures(filename):
    """Parse PDF signatures"""
    reader = PdfReader(filename)
    fields = reader.get_fields().values()
    signature_field_values = [
        f.value for f in fields if f.field_type == '/Sig']
    for v in signature_field_values:
        # - signature datetime (not included in pkcs7) in format:
        #   D:YYYYMMDDHHmmss[offset]
        #   where offset is +/-HH'mm' difference to UTC.
        v_type = v['/Type']
        if v_type in ('/Sig', '/DocTimeStamp'):  # unknow types are skipped
            is_timestamp = v_type == '/DocTimeStamp'
            try:
                signing_time = parse(v['/M'][2:].strip("'").replace("'", ":"))
            except KeyError:
                signing_time = None
            # - used standard for signature encoding, in my case:
            # - get PKCS7/CMS/CADES signature package encoded in ASN.1 / DER format
            raw_signature_data = v['/Contents']
            # if is_timestamp:
            for attrdict in parse_pkcs7_signatures(raw_signature_data):
                if attrdict:
                    # print(v)
                    attrdict.update(dict(
                        type='timestamp' if is_timestamp else 'signature',
                        signer_name=v.get('/Name'),
                        signer_contact_info=v.get('/ContactInfo'),
                        signer_location=v.get('/Location'),
                        signing_time=signing_time or attrdict.get('signing_time'),
                        signature_type=v['/SubFilter'][1:],  # ETSI.CAdES.detached, ...
                        signature_handler=v['/Filter'][1:],
                        raw=raw_signature_data,
                    ))
                    yield Signature(attrdict)



# for signature in get_pdf_signatures('firm.pdf'):
import hashlib
import binascii
import re as regex

def _format_hash(hash_bytes):
        hash_hex = binascii.hexlify(hash_bytes)
        hash_upper = hash_hex.decode('utf-8').upper()
        formated_hash = ""
        for part in regex.findall('..', hash_upper):
            formated_hash += part + ":"

        return formated_hash[:-1]

def _sha256(value):
        '''
        Makes a sha256 hash over a string value. Formats the hash to be readable
        :param value: input
        :return: formated hash
        '''
        value = value.encode('utf-8')
        sha = hashlib.sha256()
        sha.update(value)
        hash_bytes = sha.digest()
        return _format_hash(hash_bytes)

def process_base_64_pdf(base_64_pdf):
    buffer=base64.b64decode(base_64_pdf)
    f=io.BytesIO(buffer)
    signatures =  get_pdf_signatures(f)
    output = []
    # open("salida.txt","wb").write(signatures)
    for signature in signatures:
    #     print(f"--- {signature.type} ---")
    #     print(f"Signature: {signature}")
    #     print(f"Signer: {signature.signer_name}")
    #     print(f"Signing time: {signature.signing_time}")
    #     certificate = signature.certificate
    #     print(f"Signer's certificate: {certificate}")
    #     print(f"  - not before: {certificate.validity.not_before}")
    #     print(f"  - not after: {certificate.validity.not_after}")
    #     print(f"  - issuer: {certificate.issuer}")
    #     subject = signature.certificate.subject
    #     print(f"  - subject: {subject}")
    #     print(f"    - common name: {subject.common_name}")
    #     print(f"    - serial number: {subject.serial_number}")
        
        
        
    #     from cryptography.hazmat.primitives.asymmetric import rsa
    #     from cryptography.hazmat.primitives import serialization

    #     # Valores de tu clave pública
        
    #     modulus = certificate.subject_public_key_info.public_key.modulus
    #     public_exponent = certificate.subject_public_key_info.public_key.public_exponent
        
    #     # print(dir(certificate.subject_public_key_info))
    #     print(_sha256(str(certificate.subject_public_key_info.public_key)))
        
        
    #     # Crear un objeto RSAPublicKey
    #     public_key = rsa.RSAPublicNumbers(public_exponent, modulus).public_key()
    #     # print(public_key)

    #     # Serializar la clave pública a formato PEM
    #     pem = public_key.public_bytes(
    #         encoding=serialization.Encoding.PEM,
    #         format=serialization.PublicFormat.SubjectPublicKeyInfo
    #     )

        # Mostrar la clave pública en formato PEM
        print()
        
        output.append({
            "signature_type":signature.type,
            # "signature":signature,
            "signer":signature.signer_name,
            "signing_time":signature.signing_time,
            # "serial_number":signature.certificate.serial_number,
            "signers_certificate":{
                "serial_number":str(signature.certificate.serial_number),
                "common_name":str(signature.certificate.common_name),
                "version":str(signature.certificate.version)
            },
            
            "not_before":signature.certificate.validity.not_before,
            "not_after":signature.certificate.validity.not_after,
            "issuer":signature.certificate.issuer,
            "subject":signature.certificate.subject,
            "common_name":signature.certificate.subject.common_name,
                       
            # "public_key":{
            #     "modulus":pem,  
            # }
        
        })
    
        # open('public_key.pem','wb').write(pem)
        
    return output