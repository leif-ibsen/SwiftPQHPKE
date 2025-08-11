# ``SwiftPQHPKE/Recipient``

The recipient

## Overview

Based on its ``SwiftPQHPKE/CipherSuite`` a `Recipient` instance can decrypt a sequence of messages in one of two modes:

* Base mode
* Preshared key mode

> Important:
The decryption of the messages must be done in the order in which they were encrypted.

A `Recipient` instance can also retrieve generated export secrets.

## Topics

### Constructors

- ``init(suite:privateKey:info:encap:)``
- ``init(suite:privateKey:info:psk:pskId:encap:)``

### Methods

- ``open(ct:aad:)``
- ``receiveExport(context:L:)``

