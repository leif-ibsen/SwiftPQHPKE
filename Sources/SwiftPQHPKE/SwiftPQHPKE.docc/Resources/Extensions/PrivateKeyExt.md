# ``SwiftPQHPKE/PrivateKey``

The private key

## Overview

There are three different private key types corresponding to the three KEM's

* ML512 - the key is a 1632 byte value
* ML768 - the key is a 2400 byte value
* ML1024 - the key is a 3168 byte value

## Topics

### Properties

- ``bytes``
- ``publicKey``
- ``asn1``
- ``pem``
- ``description``

### Constructors

- ``init(kem:bytes:)``
- ``init(pem:)``

