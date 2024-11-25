import argparse
import os
import sys

from cryptography import x509
from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives import serialization

from src.utils import load_private_key


def load_csr(filename: str) -> x509.CertificateSigningRequest:
    """
    Loads a CSR from a file.

    Args:
        filename (str): The path to the CSR file.

    Returns:
        x509.CertificateSigningRequest: The loaded CSR.
    """
    try:
        with open(filename, "rb") as f:
            csr = x509.load_pem_x509_csr(f.read())
        return csr
    except Exception as e:
        print(f"Error loading CSR: {e}")
        sys.exit(1)


def extract_public_key_from_csr(csr: x509.CertificateSigningRequest) -> bytes:
    """
    Extracts the public key from a CSR.

    Args:
        csr (x509.CertificateSigningRequest): The CSR.

    Returns:
        bytes: The public key in PEM format.
    """
    try:
        public_key = csr.public_key()
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    except Exception as e:
        print(f"Error extracting public key from CSR: {e}")
        sys.exit(1)


def save_public_key(public_key_pem: bytes, filename: str):
    """
    Saves the public key to a file.

    Args:
        public_key_pem (bytes): The public key in PEM format.
        filename (str): The filename to save the public key to.
    """
    try:
        with open(filename, "wb") as f:
            f.write(public_key_pem)
    except Exception as e:
        print(f"Error saving public key: {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Extract and compare public keys from a private key and CSR.")
    parser.add_argument('--key-file', default='../data/private_key.pem', help="Path to the private key file.")
    parser.add_argument('--csr-file', default='../data/csr.pem', help="Path to the CSR file.")
    parser.add_argument('--output-dir', default='../data', help="Output directory for public keys.")
    parser.add_argument('--passphrase', help="Passphrase for the encrypted private key.")
    args = parser.parse_args()

    # Load private key
    private_key = load_private_key(args.key_file, args.passphrase)

    # Load CSR
    csr = load_csr(args.csr_file)

    # Extract public keys
    public_key_from_private = private_key.public_key()
    public_key_from_private_pem = public_key_from_private.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    public_key_from_csr_pem = extract_public_key_from_csr(csr)

    os.makedirs(args.output_dir, exist_ok=True)
    private_pub_key_path = os.path.join(args.output_dir, "public_key_from_private.pem")
    csr_pub_key_path = os.path.join(args.output_dir, "public_key_from_csr.pem")

    save_public_key(public_key_from_private_pem, private_pub_key_path)
    save_public_key(public_key_from_csr_pem, csr_pub_key_path)

    print("Public Key from Private Key:")
    print(public_key_from_private_pem.decode())

    print("Public Key from CSR:")
    print(public_key_from_csr_pem.decode())

    # Compare the two public keys
    if public_key_from_private_pem == public_key_from_csr_pem:
        print("The public keys match!")
    else:
        print("The public keys do not match.")


if __name__ == "__main__":
    main()
