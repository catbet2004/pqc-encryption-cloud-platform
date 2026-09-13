# Post-Quantum Secure Cloud Platform

## Overview

The Post-Quantum Secure Cloud Platform is an experimental post-quantum secure file transfer and cloud platform. The project explores how standarized post-qunatum cryptographic algorithms can be used to protect files and establish secure communication against both classical and future quantum threats.

## Insight on Algorithms

### ML-KEM-768

ML-KEM is a post-qunatum Key Encapsulation Mechanism that is used to establish a shared secret between two users without directly transmitting that secret.

### ML-DSA-65

ML-DSA is a post-quantum digital signature algorithm that is used to verify the authenticity and integrity of messages, files, and cryptographic metadata.

### HKDF

HKDF is used to derive cryptographic key material from the shared secret produced by ML-KEM.

### AES-256-GCM

AES-256-GCM is used to encrypt the actual files and provide authenticated encryption.

(ML-KEM establishes the secret used to create the encryption key, while AES-256-GCM performs the actual file encryption)


## Notes

- This project is still in development...
