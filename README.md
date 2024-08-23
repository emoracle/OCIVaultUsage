Using OCI Vault ( the public KMS version) to encrypt and decrypt.

Both AES-256 symmetric key as RSA - PKI are used.

Also, encryption with a public cert using Crypto and decrypting using oci-keymanagement is also included.

At time of writing, 20 HSM-keys are free of charge. Software HSM keys are free.

You need:

1. A working oci-cli infrastructure
2. an ocid of the compartment
3. An ocid of keys, vaults e.a. when already created.

