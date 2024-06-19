from cryptography import x509
from cryptography.hazmat.backends import default_backend
import PyPDF2

def extraer_certificado_desde_pdf(pdf_path):
    certificado = None
    with open(pdf_path, 'rb') as pdf_file:
        pdf_reader = PyPDF2.PdfFileReader(pdf_file)
        first_page = pdf_reader.getPage(0)
        for annotation in first_page['/Annots']:
            print(annotation)
            if annotation['/Subtype'] == '/Widget' and annotation['/T'] == 'FirmaDigital1':
                if '/AP' in annotation:
                    ap_dict = annotation['/AP']
                    if '/N' in ap_dict:
                        ap_stream = ap_dict['/N']
                        if isinstance(ap_stream, PyPDF2.generic.StreamObject):
                            certificado = ap_stream.get_data()
                            break
    return certificado

def decodificar_certificado(certificado):
    cert = x509.load_der_x509_certificate(certificado, default_backend())
    return cert

# Ruta al archivo PDF
pdf_path = 'test.pdf'

# Extraer el certificado del PDF
certificado_binario = extraer_certificado_desde_pdf(pdf_path)

if certificado_binario:
    # Decodificar el certificado
    certificado = decodificar_certificado(certificado_binario)
    print("Certificado decodificado correctamente:", certificado)
else:
    print("No se pudo encontrar un certificado en el PDF.")
