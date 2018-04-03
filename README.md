# EDHOC-C
Implementation of Ephemeral Diffie-Hellman Over COSE (EDHOC) in C.

EDHOC specification: [EDHOC](https://datatracker.ietf.org/doc/draft-selander-ace-cose-ecdhe/)

EDHOC is a key exchange protocol designed to run over CoAP or OSCOAP. The communicating parties run an Elliptic Curve Diffie-Hellman (ECDH) key exchange protocol with ephemeral keys, from which a shared secret is derived. EDHOC messages are encoded with the Consise Binary Object Representation (CBOR) format which is based on the Javascript Object Notation (JSON) data model and the CBOR Object Signing and Encryption (COSE) which specifies how to process encryption, signatures and Message Authentication Code (MAC) operations, and how to encode keys using JSON. 

## Supported authentication
EDHOC supports authentication using pre-shared keys (PSK), raw public keys (RPK) and certificates (Cert).

### Dependencies
OpenSSL version 1.1.0 (includes X25519 elliptic curve) or newer

libb64 (Base64 Encoding/Decoding Routines)

libcbor (CBOR format implementation for C)

### Usage
```sh
$ cd EDHOC-C/src
$ make clean && make
$ ./edhoc-client
```
Open a new terminal in the same directory and run the server
```
$ ./edhoc-server
```

### TODO
CoAP integration

Certificate enrollment over EDHOC

Add documentation
