from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime

def generate_self_signed_cert(cert_file="./cert.pem", key_file="./key.pem"):
    # Create a private key
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Define certificate subject and issuer
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Gujarat"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Surat"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Harsh"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Harsh SAD Project"),
    ])

    # Create the certificate
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    # Save the private key
    with open(key_file, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Save the certificate
    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print("✅ Self-signed certificate and key generated successfully!")

# Generate SSL certs
generate_self_signed_cert()
