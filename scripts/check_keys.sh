#!/bin/bash

# Ensure both key and csr are provided
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <private_key_file> <csr_file>"
    exit 1
fi

# Assign arguments to variables
private_key_file=$1
csr_file=$2

# Function to extract the public key from the private key file
get_public_key_from_private_key() {
    local key_file=$1
    openssl rsa -in "$key_file" -pubout 2>/dev/null
}

# Function to extract the public key from the CSR file
get_public_key_from_csr() {
    local csr_file=$1
    openssl req -in "$csr_file" -pubkey -noout 2>/dev/null
}

# Extract the public key from the private key and CSR
private_key_public=$(get_public_key_from_private_key "$private_key_file")
csr_public=$(get_public_key_from_csr "$csr_file")

# Print the public keys
echo "Public Key from Private Key:"
echo "$private_key_public"
echo
echo "Public Key from CSR:"
echo "$csr_public"
echo

# Compare the two public keys
if [ "$private_key_public" == "$csr_public" ]; then
    echo "The public keys match!"
else
    echo "The public keys do not match."
fi
