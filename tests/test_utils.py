import pytest
from src.utils import validate_key_size, load_private_key
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

def test_validate_key_size():
    assert validate_key_size("2048") == 2048
    assert validate_key_size("4096") == 4096

    with pytest.raises(SystemExit):
        validate_key_size("1024")

    with pytest.raises(SystemExit):
        validate_key_size("invalid")

@pytest.fixture
def mock_private_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

def test_load_private_key(mock_private_key, tmp_path):
    # Create a temporary private key file
    key_file = tmp_path / "test_private_key.pem"
    key_file.write_bytes(
        mock_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
    )

    # Test loading the private key
    loaded_key = load_private_key(str(key_file), None)
    assert isinstance(loaded_key, rsa.RSAPrivateKey)

    # Test with invalid file
    with pytest.raises(SystemExit):
        load_private_key("invalid_file.pem", None)