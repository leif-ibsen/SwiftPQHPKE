# Encryption and Decryption

Encrypt and decrypt one or more messages

##

### Stateless Single-shot API

A `CipherSuite` instance can encrypt (seal) a single plaintext message and decrypt (open) a single
ciphertext message without the need for a `Sender` instance and a `Recipient` instance.

**Example**

```swift
// Encryption and decryption of a single message in base mode

import SwiftPQHPKE

// The CipherSuite to use
let theSuite = CipherSuite(kem: .ML512, kdf: .KDF256, aead: .AESGCM256)

// The recipient keys
let (recipientPub, recipientPriv) = theSuite.makeKeyPair()

let plainText = Bytes("Hi, there".utf8)
let theInfo: Bytes = [1, 2, 3]
let theAad: Bytes = [4, 5, 6]

// Generate the ciphertext
let (encapsulatedKey, cipherText) = try theSuite.seal(publicKey: recipientPub, info: theInfo, pt: plainText, aad: theAad)

// Decrypt it
let decrypted = try theSuite.open(privateKey: recipientPriv, info: theInfo, ct: cipherText, aad: theAad, encap: encapsulatedKey)
print(String(bytes: decrypted, encoding: .utf8)!)
```
giving:
```swift
Hi, there
```

### Stateful Multi-message API

A `Sender` is based on a specific `CipherSuite` and a `Sender` instance can encrypt (seal)
a sequence of plaintexts.

A `Recipient` is also based on a specific `CipherSuite` and a `Recipient` instance can decrypt (open)
a sequence of ciphertexts.

**Example**

```swift
// Encryption and decryption of 3 messages in preshared key mode

import SwiftPQHPKE

// The CipherSuite to use
let theSuite = CipherSuite(kem: .ML768, kdf: .KDF384, aead: .CHACHAPOLY)

let plainText1 = Bytes("Hi, there 1".utf8)
let plainText2 = Bytes("Hi, there 2".utf8)
let plainText3 = Bytes("Hi, there 3".utf8)

let thePsk: Bytes = [1]
let thePskId: Bytes = [2]
let theInfo: Bytes = [1, 2, 3]
let aad1: Bytes = [4, 5]
let aad2: Bytes = [6, 7]
let aad3: Bytes = [8, 9]

// The Recipient keys
let (recipientPub, recipientPriv) = theSuite.makeKeyPair()

// Create the Sender instance
let sender = try Sender(suite: theSuite, publicKey: recipientPub, info: theInfo, psk: thePsk, pskId: thePskId)

// Generate the ciphertexts
let cipherText1 = try sender.seal(pt: plainText1, aad: aad1)
let cipherText2 = try sender.seal(pt: plainText2, aad: aad2)
let cipherText3 = try sender.seal(pt: plainText3, aad: aad3)

// Create the Recipient instance
let recipient = try Recipient(suite: theSuite, privateKey: recipientPriv, info: theInfo, psk: thePsk, pskId: thePskId, encap: sender.encapsulatedKey)

// Decrypt the ciphertexts
let decrypted1 = try recipient.open(ct: cipherText1, aad: aad1)
let decrypted2 = try recipient.open(ct: cipherText2, aad: aad2)
let decrypted3 = try recipient.open(ct: cipherText3, aad: aad3)

print(String(bytes: decrypted1, encoding: .utf8)!)
print(String(bytes: decrypted2, encoding: .utf8)!)
print(String(bytes: decrypted3, encoding: .utf8)!)
```
giving:
```swift
Hi, there 1
Hi, there 2
Hi, there 3
```

> Important:
The messages must be decrypted in the order in which they were encrypted.
