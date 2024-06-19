from lxml import etree

def get_certificate_from_xml_by_subject(xml_path, subject_name):
    tree = etree.parse(xml_path)
    namespaces = {
        'tsl': 'http://uri.etsi.org/02231/v2#',
        'ds': 'http://www.w3.org/2000/09/xmldsig#'
    }
    for ServiceDigitalIdentity in tree.xpath('//tsl:ServiceDigitalIdentity', namespaces=namespaces):
        x509_subject = ServiceDigitalIdentity.xpath('.//tsl:DigitalId', namespaces=namespaces)
        # print(x509_subject)
        # print()
        X509SubjectName = x509_subject[1].xpath('.//text()')[1]
        certificate = x509_subject[0].xpath('.//text()')[1]
        
        # print('\n',X509SubjectName,'\n')
        if (subject_name in X509SubjectName):
            print(X509SubjectName)
            print(certificate)
            return (X509SubjectName,certificate)
        
        # if x509_subject and subject_name in x509_subject[0]:
        #     print(x509_subject)
        #     certificates = digital_id.xpath('.//tsl:X509Certificate/text()', namespaces=namespaces)
        #     if certificates:
        #         return certificates
    return None

# Ruta al archivo XML
xml_path = 'list.xml'
subject_name = "CN=ECEP-RENIEC"
# Usar el nombre del sujeto extraído del PDF
if subject_name:
    certificates = get_certificate_from_xml_by_subject(xml_path, subject_name)
    
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    import base64

    # Certificado en formato base64 (sin los encabezados y pies de página PEM)
    
    # Convertir el certificado base64 a objeto x509
    cert_der = base64.b64decode(certificates[1])
    cert = x509.load_der_x509_certificate(cert_der)

    # Convertir el certificado x509 a formato PEM
    pem = cert.public_bytes(encoding=serialization.Encoding.PEM)

    # Guardar el certificado PEM en un archivo
    with open("ca.pem", "wb") as pem_out:
        pem_out.write(pem)

    print(pem.decode('utf-8'))

    
    
    if certificates:
        print("Certificados X509 encontrados en el XML para el nombre del sujeto dado:")
        for cert in certificates:
            print(cert)
    else:
        print("No se encontraron certificados X509 para el nombre del sujeto especificado en el XML.")
else:
    print("No se proporcionó el nombre del sujeto para la búsqueda en el XML.")
