import sys
from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def get_user_input() -> dict:
    """
    Collects user input for CSR details.

    Returns:
        dict: A dictionary containing the CSR subject details and key parameters.
    """
    print("Enter the following details to generate CSR:")
    
    details = {}
    try:
        details['common_name'] = input("Common Name (Hostname): ").strip()
        details['organization'] = input("Organization: ").strip()
        details['organizational_unit'] = input("Organizational Unit: ").strip()
        details['locality'] = input("City / Locality: ").strip()
        details['state'] = input("State / Region: ").strip()
        details['country'] = input("Country (2-letter code): ").strip()
        details['key_size'] = input("Key Size (e.g., 2048, 4096): ").strip()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(1)
    return details


def validate_key_size(key_size_str: str) -> int:
    """
    Validates and returns the key size as an integer.

    Args:
        key_size_str (str): The key size input as a string.

    Returns:
        int: The validated key size.

    Raises:
        ValueError: If the key size is invalid.
    """
    try:
        key_size = int(key_size_str)
        if key_size not in [2048, 3072, 4096]:
            raise ValueError("Invalid key size. Choose 2048, 3072, or 4096.")
        return key_size
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)


def load_private_key(filename: str, passphrase: Optional[str]) -> rsa.RSAPrivateKey:
    """
    Loads a private key from a file.

    Args:
        filename (str): The path to the private key file.
        passphrase (Optional[str]): The passphrase for the private key.

    Returns:
        rsa.RSAPrivateKey: The loaded private key.
    """
    try:
        with open(filename, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=passphrase.encode() if passphrase else None,
            )
        return private_key
    except Exception as e:
        print(f"Error loading private key: {e}")
        sys.exit(1)
