import argparse
import os
import sys
import datetime
from typing import Optional

from cryptography import x509
from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from src.utils import get_user_input, validate_key_size

def generate_private_key(key_size: int) -> rsa.RSAPrivateKey:
    """
    Generates an RSA private key.

    Args:
        key_size (int): The size of the key in bits.

    Returns:
        rsa.RSAPrivateKey: The generated private key.
    """
    try:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )
        return private_key
    except ValueError as e:
        print(f"Error generating private key: {e}")
        sys.exit(1)

def create_csr(private_key: rsa.RSAPrivateKey, details: dict) -> x509.CertificateSigningRequest:
    """
    Creates a Certificate Signing Request (CSR).

    Args:
        private_key (rsa.RSAPrivateKey): The private key to sign the CSR.
        details (dict): Subject details for the CSR.

    Returns:
        x509.CertificateSigningRequest: The generated CSR.
    """
    try:
        csr_builder = x509.CertificateSigningRequestBuilder()
        csr_builder = csr_builder.subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, details['common_name']),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, details['organization']),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, details['organizational_unit']),
            x509.NameAttribute(NameOID.LOCALITY_NAME, details['locality']),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, details['state']),
            x509.NameAttribute(NameOID.COUNTRY_NAME, details['country']),
        ]))
        csr = csr_builder.sign(private_key, hashes.SHA256())
        return csr
    except Exception as e:
        print(f"Error creating CSR: {e}")
        sys.exit(1)

def save_private_key(private_key: rsa.RSAPrivateKey, filename: str, passphrase: Optional[bytes]):
    """
    Saves the private key to a file.

    Args:
        private_key (rsa.RSAPrivateKey): The private key to save.
        filename (str): The filename to save the key to.
        passphrase (Optional[bytes]): Passphrase to encrypt the key.
    """
    try:
        encryption_algo = serialization.NoEncryption()
        if passphrase:
            encryption_algo = serialization.BestAvailableEncryption(passphrase)
        with open(filename, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=encryption_algo
            ))
    except Exception as e:
        print(f"Error saving private key: {e}")
        sys.exit(1)

def save_csr(csr: x509.CertificateSigningRequest, filename: str):
    """
    Saves the CSR to a file.

    Args:
        csr (x509.CertificateSigningRequest): The CSR to save.
        filename (str): The filename to save the CSR to.
    """
    try:
        with open(filename, "wb") as f:
            f.write(csr.public_bytes(serialization.Encoding.PEM))
    except Exception as e:
        print(f"Error saving CSR: {e}")
        sys.exit(1)

def generate_self_signed_cert(private_key: rsa.RSAPrivateKey, details: dict, filename: str):
    """
    Generates a self-signed certificate.

    Args:
        private_key (rsa.RSAPrivateKey): The private key to sign the certificate.
        details (dict): Subject details for the certificate.
        filename (str): The filename to save the certificate to.
    """
    try:
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, details['common_name']),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, details['organization']),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, details['organizational_unit']),
            x509.NameAttribute(NameOID.LOCALITY_NAME, details['locality']),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, details['state']),
            x509.NameAttribute(NameOID.COUNTRY_NAME, details['country']),
        ])
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).sign(private_key, hashes.SHA256())

        with open(filename, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        print(f"Self-signed certificate saved to {filename}")
    except Exception as e:
        print(f"Error generating self-signed certificate: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Generate a private key and CSR.")
    parser.add_argument('--encrypt-key', action='store_true', help="Encrypt the private key with a passphrase.")
    parser.add_argument('--output-dir', default='../data', help="Output directory for generated files.")
    parser.add_argument('--self-signed', action='store_true', help="Generate a self-signed certificate.")
    args = parser.parse_args()

    # Get user input
    details = get_user_input()
    key_size = validate_key_size(details['key_size'])

    # Generate private key
    private_key = generate_private_key(key_size)
    os.makedirs(args.output_dir, exist_ok=True)

    # Encrypt private key if requested
    passphrase = None
    if args.encrypt_key:
        passphrase_input = input("Enter passphrase for private key encryption: ")
        passphrase = passphrase_input.encode()

    private_key_path = os.path.join(args.output_dir, "private_key.pem")
    save_private_key(private_key, private_key_path, passphrase)
    print(f"Private key saved to {private_key_path}")

    # Generate CSR
    csr = create_csr(private_key, details)
    csr_path = os.path.join(args.output_dir, "csr.pem")
    save_csr(csr, csr_path)
    print(f"CSR saved to {csr_path}")

    # Generate self-signed certificate if requested
    if args.self_signed:
        cert_path = os.path.join(args.output_dir, "self_signed_certificate.pem")
        generate_self_signed_cert(private_key, details, cert_path)

if __name__ == "__main__":
    main()