import pytest
from src.compare_keys import load_csr, extract_public_key_from_csr, save_public_key
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa

@pytest.fixture
def mock_csr():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, u"test.com"),
    ])).sign(private_key, hashes.SHA256())
    return csr

def test_load_csr(mock_csr, tmp_path):
    csr_file = tmp_path / "test_csr.pem"
    csr_file.write_bytes(mock_csr.public_bytes(serialization.Encoding.PEM))

    loaded_csr = load_csr(str(csr_file))
    assert isinstance(loaded_csr, x509.CertificateSigningRequest)

def test_extract_public_key_from_csr(mock_csr):
    public_key_pem = extract_public_key_from_csr(mock_csr)
    assert isinstance(public_key_pem, bytes)
    assert public_key_pem.startswith(b'-----BEGIN PUBLIC KEY-----')

def test_save_public_key(tmp_path):
    public_key_pem = b'-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END PUBLIC KEY-----\n'
    test_file = tmp_path / "test_public_key.pem"
    save_public_key(public_key_pem, str(test_file))
    assert test_file.read_bytes() == public_key_pem