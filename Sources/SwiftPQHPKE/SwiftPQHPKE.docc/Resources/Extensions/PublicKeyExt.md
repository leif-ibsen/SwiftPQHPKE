# ``SwiftPQHPKE/PublicKey``

The public key

## Overview

There are three different public key types corresponding to the three KEM's

* ML512 - the key is a 800 byte value
* ML768 - the key is a 1184 byte value
* ML1024 - the key is a 1568 byte value

## Topics

### Properties

- ``bytes``
- ``asn1``
- ``pem``
- ``description``

### Constructors

- ``init(kem:bytes:)``
- ``init(pem:)``


