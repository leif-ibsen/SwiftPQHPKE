# ``SwiftPQHPKE``

Post-Quantum Hybrid Public Key Encryption

## Overview

SwiftPQHPKE implements part of the Hybrid Public Key Encryption standard as defined in [[RFC 9180]](https://datatracker.ietf.org/doc/rfc9180/). It differs from the standard in the following ways:

* Its key encapsulation mechanisms are: ML-KEM-512, ML-KEM-768 and ML-KEM-1024 as defined in the [[FIPS 203]](https://csrc.nist.gov/pubs/fips/203/final).
  The corresponding KEM IDs are: 0x0040, 0x0041 and 0x0042.
* It only implements base mode and preshared key mode, not authenticated mode and authenticated preshared key mode

The basic concepts in SwiftPQHPKE are `CipherSuite`, `Sender` and `Recipient`, represented by the ``SwiftPQHPKE/CipherSuite`` structure and the ``SwiftPQHPKE/Sender`` and ``SwiftPQHPKE/Recipient`` classes.

A CipherSuite combines a *Key Encapsulation Mechanism* (``SwiftPQHPKE/KEM``), a *Key Derivation Function* (``SwiftPQHPKE/KDF``)
and an *Authenticated Encryption with Associated Data* (``SwiftPQHPKE/AEAD``) algorithm.

There are 3 different KEM's, 3 different KDF's and 4 different AEAD's giving 36 CipherSuite combinations.

The basic functionality of SwiftPQHPKE is encryption and decryption of arbitrarily sized plain text messages.
Encryption and decryption take place in one of two modes:

* Base mode
* Preshared key mode

For examples of encryption and decryption, please see <doc:EncryptDecrypt>.

SwiftPQHPKE can also generate secret export messages that only the recipient of the messages can know.
This also take place in either Base mode or Preshared key mode.

For examples of secret export, please see <doc:SecretExport>.

### Usage

To use SwiftPQHPKE, in your project *Package.swift* file add a dependency like

```swift
dependencies: [
  .package(url: "https://github.com/leif-ibsen/SwiftPQHPKE", from: "1.0.0"),
]
```

SwiftPQHPKE itself depends on the [ASN1](https://leif-ibsen.github.io/ASN1/documentation/asn1), [BigInt](https://leif-ibsen.github.io/BigInt/documentation/bigint), [Digest](https://leif-ibsen.github.io/Digest/documentation/digest) and [SwiftKyber](https://leif-ibsen.github.io/SwiftKyber/documentation/swiftkyber) packages

```swift
dependencies: [
  .package(url: "https://github.com/leif-ibsen/ASN1", from: "2.7.0"),
  .package(url: "https://github.com/leif-ibsen/BigInt", from: "1.21.0"),
  .package(url: "https://github.com/leif-ibsen/Digest", from: "1.13.0"),
  .package(url: "https://github.com/leif-ibsen/SwiftKyber", from: "3.4.0"),
],
```

SwiftPQHPKE does not do big integer arithmetic, but the ASN1 package depends on the BigInt package.

> Important:
SwiftPQHPKE requires Swift 5.0. It also requires that the `Int` and `UInt` types be 64 bit types.
>
> SwiftPQHPKE uses Apple’s CryptoKit framework. Therefore, for macOS the version must be at least 10.15,
for iOS the version must be at least 13, and for watchOS the version must be at least 8.

## Topics

### Structures

- ``SwiftPQHPKE/CipherSuite``
- ``SwiftPQHPKE/PrivateKey``
- ``SwiftPQHPKE/PublicKey``

### Classes

- ``SwiftPQHPKE/Sender``
- ``SwiftPQHPKE/Recipient``

### Type Aliases

- ``SwiftPQHPKE/Byte``
- ``SwiftPQHPKE/Bytes``

### Enumerations

- ``SwiftPQHPKE/AEAD``
- ``SwiftPQHPKE/KDF``
- ``SwiftPQHPKE/KEM``
- ``SwiftPQHPKE/HPKEException``

### Additional Information

- <doc:EncryptDecrypt>
- <doc:SecretExport>
- <doc:KeyManagement>
- <doc:Performance>
- <doc:References>

