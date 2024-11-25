import pytest
from src.generate_csr import (
    generate_private_key, 
    create_csr, 
    save_private_key, 
    save_csr, 
    generate_self_signed_cert
)
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509

def test_generate_private_key():
    private_key = generate_private_key(2048)
    assert isinstance(private_key, rsa.RSAPrivateKey)
    assert private_key.key_size == 2048

def test_create_csr():
    private_key = generate_private_key(2048)
    details = {
        'common_name': 'test.com',
        'organization': 'Test Org',
        'organizational_unit': 'IT',
        'locality': 'Test City',
        'state': 'Test State',
        'country': 'US'
    }
    csr = create_csr(private_key, details)
    assert isinstance(csr, x509.CertificateSigningRequest)

def test_save_private_key(tmp_path):
    private_key = generate_private_key(2048)
    key_file = tmp_path / "test_private_key.pem"
    save_private_key(private_key, str(key_file), None)
    assert key_file.exists()
    assert key_file.read_bytes().startswith(b'-----BEGIN PRIVATE KEY-----') or key_file.read_bytes().startswith(b'-----BEGIN RSA PRIVATE KEY-----')

def test_save_csr(tmp_path):
    private_key = generate_private_key(2048)
    details = {
        'common_name': 'test.com',
        'organization': 'Test Org',
        'organizational_unit': 'IT',
        'locality': 'Test City',
        'state': 'Test State',
        'country': 'US'
    }
    csr = create_csr(private_key, details)
    csr_file = tmp_path / "test_csr.pem"
    save_csr(csr, str(csr_file))
    assert csr_file.exists()
    assert csr_file.read_bytes().startswith(b'-----BEGIN CERTIFICATE REQUEST-----')

def test_generate_self_signed_cert(tmp_path):
    private_key = generate_private_key(2048)
    details = {
        'common_name': 'test.com',
        'organization': 'Test Org',
        'organizational_unit': 'IT',
        'locality': 'Test City',
        'state': 'Test State',
        'country': 'US'
    }
    cert_file = tmp_path / "test_cert.pem"
    generate_self_signed_cert(private_key, details, str(cert_file))
    assert cert_file.exists()
    assert cert_file.read_bytes().startswith(b'-----BEGIN CERTIFICATE-----')