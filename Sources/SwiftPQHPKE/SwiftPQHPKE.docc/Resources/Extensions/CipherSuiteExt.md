# ``SwiftPQHPKE/CipherSuite``

The cipher suite

## Overview

A `CipherSuite` instance combines a *Key Encapsulation Mechanism* (``SwiftPQHPKE/KEM``), a *Key Derivation Function* (``SwiftPQHPKE/KDF``)
and a *AEAD Encryption Algorithm* (``SwiftPQHPKE/AEAD``).

It can encrypt or decrypt a single message and generate or retrieve an export secret in one of two modes:

* Base mode
* Preshared key mode

## Topics

### Properties

- ``kem``
- ``kdf``
- ``aead``
- ``description``

### Conctructor

- ``init(kem:kdf:aead:)``

### Generate Keys

- ``makeKeyPair()``
- ``deriveKeyPair(ikm:)``

### Base mode

- ``seal(publicKey:info:pt:aad:)``
- ``open(privateKey:info:ct:aad:encap:)``
- ``sendExport(publicKey:info:context:L:)``
- ``receiveExport(privateKey:info:context:L:encap:)``

### Preshared key mode

- ``seal(publicKey:info:psk:pskId:pt:aad:)``
- ``open(privateKey:info:psk:pskId:ct:aad:encap:)``
- ``sendExport(publicKey:info:context:L:psk:pskId:)``
- ``receiveExport(privateKey:info:context:L:psk:pskId:encap:)``
