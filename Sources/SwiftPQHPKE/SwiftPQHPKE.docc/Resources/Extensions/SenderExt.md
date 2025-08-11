# ``SwiftPQHPKE/Sender``

The sender

## Overview

Based on its ``SwiftPQHPKE/CipherSuite`` a `Sender` instance can encrypt a sequence of messages in one of two modes:

* Base mode
* Preshared key mode
 
A `Sender` instance can also generate export secrets that only the recipient can know.

## Topics

### Properties

- ``encapsulatedKey``

### Constructors

- ``init(suite:publicKey:info:)``
- ``init(suite:publicKey:info:psk:pskId:)``

### Methods

- ``seal(pt:aad:)``
- ``sendExport(context:L:)``
