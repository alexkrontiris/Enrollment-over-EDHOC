# Enrollment over EDHOC-C
Implementation of Certificate Enrollment over EDHOC (Ephemeral Diffie-Hellman Over COSE) in C.

EDHOC specification: [EDHOC](https://datatracker.ietf.org/doc/draft-selander-ace-cose-ecdhe/)

EDHOC is a key exchange protocol designed to run over CoAP or OSCOAP. The communicating parties run an Elliptic Curve Diffie-Hellman (ECDH) key exchange protocol with ephemeral keys, from which a shared secret is derived. EDHOC messages are encoded with the Consise Binary Object Representation (CBOR) format which is based on the Javascript Object Notation (JSON) data model and the CBOR Object Signing and Encryption (COSE) which specifies how to process encryption, signatures and Message Authentication Code (MAC) operations, and how to encode keys using JSON. 

Enrollment over EDHOC leverages the messages of the EDHOC protocol and the CMC specification to perform certificate enrollment. There is a single additional message in comparison to standalone EDHOC and it is used to carry the generated certificate to the client fromt the CA. Due to the security properties of the SIGMA protocol family which EDHOC is based on, the additional message is a requirement for maintaining those properties.

## Supported authentication
EDHOC supports authentication using pre-shared keys (PSK), raw public keys (RPK) and certificates (Cert).

## Supported key generation used for enrollment
Enrollment over EDHOC aims to be efficient and lightweight, an ideal candidate for IoT constrained devices. Thus, Elliptic Curve 256 bit keys (NIST: P-256, prime256v1 in OpenSSL) are used. The implementation also includes support for 2048 bit RSA keys.

### Dependencies
OpenSSL version 1.1.0 (includes X25519 elliptic curve) or newer

libb64 (Base64 Encoding/Decoding Routines)

libcbor (CBOR format implementation for C)

### Usage
```sh
$ cd Enrollment-over-EDHOC/src
$ make clean && make
$ ./edhoc-client
```
Open a new terminal in the same directory and run the server
```
$ ./edhoc-server
```

### TODO
CoAP integration

Add documentation
