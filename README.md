# SSL Certificate Generator

A Python-based tool for generating RSA private keys, creating Certificate Signing Requests (CSRs), and comparing public keys from private keys and CSRs. It leverages the `cryptography` library to simplify SSL certificate management.

## Table of Contents

- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
  - [Generate Private Key and CSR](#generate-private-key-and-csr)
  - [Compare Public Keys](#compare-public-keys)
- [Examples](#examples)
- [Contributing](#contributing)
- [License](#license)

## Features

- **Generate RSA Private Keys:** Supports key sizes of 2048, 3072, and 4096 bits.
- **Create Certificate Signing Requests (CSRs):** Collects user input for CSR details.
- **Generate Self-Signed Certificates:** Optionally create self-signed certificates.
- **Compare Public Keys:** Extract and compare public keys from private keys and CSRs.

## Prerequisites

- **Python 3.6 or higher**
- **pip** (Python package manager)

## Installation

Install the `ssl_cert_generator` package from PyPI using `pip`:
```bash
pip install ssl_cert_generator
```

## Usage

The `ssl_cert_generator` provides command-line interfaces to generate private keys, create CSRs, and compare public keys.

### Generate Private Key and CSR

Use the `generate_csr` command to generate an RSA private key and a CSR. You can optionally encrypt the private key with a passphrase and generate a self-signed certificate.

**Basic Command:**
```bash
generate_csr
```

**Options:**

- `--encrypt-key`: Encrypt the private key with a passphrase.
- `--output-dir`: Specify the output directory for generated files. Defaults to `./data`.
- `--self-signed`: Generate a self-signed certificate.

**Example:**
```bash
generate_csr --encrypt-key --self-signed --output-dir ./certs
```

**Interactive Prompts:**

You'll be prompted to enter the following details:

- Common Name (Hostname)
- Organization
- Organizational Unit
- City / Locality
- State / Region
- Country (2-letter code)
- Key Size (e.g., 2048, 3072, 4096)

If you choose to encrypt the private key, you'll be prompted to enter a passphrase.

### Compare Public Keys

Use the `compare_keys` command to extract and compare public keys from a private key and a CSR.

**Basic Command:**
```bash
compare_keys
```

**Options:**

- `--key-file`: Path to the private key file. Defaults to `./data/private_key.pem`.
- `--csr-file`: Path to the CSR file. Defaults to `./data/csr.pem`.
- `--output-dir`: Output directory for public keys. Defaults to `./data`.
- `--passphrase`: Passphrase for the encrypted private key, if applicable.

**Example:**
```bash
compare_keys --key-file ./certs/private_key.pem --csr-file ./certs/csr.pem --output-dir ./certs
```


**Output:**

The command will save the extracted public keys to the specified output directory and indicate whether the public keys match.

## Examples

### Example 1: Generate an Encrypted Private Key and CSR with Self-Signed Certificate
```bash
generate_csr --encrypt-key --self-signed --output-dir ./certs
```

**Sample Interaction:**
```
Enter the following details to generate CSR:
Common Name (Hostname): example.com
Organization: Example Corp
Organizational Unit: IT
City / Locality: New York
State / Region: NY
Country (2-letter code): US
Key Size (e.g., 2048, 3072, 4096): 2048
Enter passphrase for private key encryption:
Private key saved to ./certs/private_key.pem
CSR saved to ./certs/csr.pem
Self-signed certificate saved to ./certs/self_signed_certificate.pem
```

### Example 2: Compare Public Keys from Private Key and CSR
```bash
compare_keys --key-file ./certs/private_key.pem --csr-file ./certs/csr.pem --output-dir ./certs
```

**Sample Output:**
```
Public Key from Private Key:
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArQwLcxdw0xjLcWek4Epl
...
-----END PUBLIC KEY-----
Public Key from CSR:
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArQwLcxdw0xjLcWek4Epl
...
-----END PUBLIC KEY-----
The public keys match!
```

*If the public keys do not match, the output will indicate accordingly.*

## Contributing

Contributions are welcome! Please follow these steps:

1. **Fork the Repository**

2. **Create a Feature Branch**

   ```bash
   git checkout -b feature-name
   ```

3. **Commit Your Changes**

   ```bash
   git commit -m "Add feature"
   ```

4. **Push to the Branch**

   ```bash
   git push origin feature-name
   ```

5. **Open a Pull Request**

Provide a clear description of the changes and any relevant context.

## License

This project is licensed under the [Apache-2.0 license](LICENSE).
