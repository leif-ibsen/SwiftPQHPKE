# Secret Export

Create secret messages

## 

### Single Secret Export

Given the recipient's public key, a `CipherSuite` instance can generate a secret that only the recipient can know.

**Example**

```swift
// Generate secret in base mode

import SwiftPQHPKE

// The aead need not be .EXPORTONLY, any aead will work

// The CipherSuite to use
let theSuite = CipherSuite(kem: .ML512, kdf: .KDF256, aead: .EXPORTONLY)

// The recipient keys
let (recipientPubKey, recipientPrivKey) = theSuite.makeKeyPair()

// Generate the secret
let (encapsulated, secret) = try theSuite.sendExport(publicKey: recipientPubKey, info: [], context: [], L: 10)
print("Generated secret:", secret)

// The recipient retrieves the secret by means of the encapsulated key
let retrievedSecret = try theSuite.receiveExport(privateKey: recipientPrivKey, info: [], context: [], L: 10, encap: encapsulated)
print("Retrieved secret:", retrievedSecret)
```
giving (for example):
```swift
Generated secret: [214, 237, 48, 14, 75, 122, 60, 137, 232, 222]
Retrieved secret: [214, 237, 48, 14, 75, 122, 60, 137, 232, 222]
```

### Multi-secret Export

Given the recipient's public key, a `Sender` instance can generate secrets that only the recipient can know.

**Example**

```swift
// Generate 3 secrets in preshared key mode

import SwiftPQHPKE

// The aead need not be .EXPORTONLY, any aead will work

// The CipherSuite to use
let theSuite = CipherSuite(kem: .ML512, kdf: .KDF256, aead: .EXPORTONLY)

let thePsk: Bytes = [1]
let thePskId: Bytes = [2]
let theInfo: Bytes = [1, 2, 3]

// The Recipient keys
let (recipientPubKey, recipientPrivKey) = theSuite.makeKeyPair()

// Create the Sender instance
let sender = try Sender(suite: theSuite, publicKey: recipientPubKey, info: theInfo, psk: thePsk, pskId: thePskId)

let ctx1: Bytes = [1]
let ctx2: Bytes = [2]
let ctx3: Bytes = [3]

// Generate the secrets
let secret1 = try sender.sendExport(context: ctx1, L: 10)
let secret2 = try sender.sendExport(context: ctx2, L: 10)
let secret3 = try sender.sendExport(context: ctx3, L: 10)
print("Generated secret1:", secret1)
print("Generated secret2:", secret2)
print("Generated secret3:", secret3)
print()

// Create the Recipient instance, the recipient retrieves the secrets by means of the encapsulated key
let recipient = try Recipient(suite: theSuite, privateKey: recipientPrivKey, info: theInfo, psk: thePsk, pskId: thePskId, encap: sender.encapsulatedKey)

// Retrieve the secrets
let retrievedSecret1 = try recipient.receiveExport(context: ctx1, L: 10)
let retrievedSecret2 = try recipient.receiveExport(context: ctx2, L: 10)
let retrievedSecret3 = try recipient.receiveExport(context: ctx3, L: 10)
print("Retrieved secret1:", retrievedSecret1)
print("Retrieved secret2:", retrievedSecret2)
print("Retrieved secret3:", retrievedSecret3)
```
giving (for example):
```swift
Generated secret1: [69, 227, 178, 197, 20, 38, 132, 235, 147, 90]
Generated secret2: [165, 213, 95, 210, 19, 71, 144, 70, 189, 32]
Generated secret3: [98, 6, 38, 67, 130, 142, 230, 207, 1, 128]

Retrieved secret1: [69, 227, 178, 197, 20, 38, 132, 235, 147, 90]
Retrieved secret2: [165, 213, 95, 210, 19, 71, 144, 70, 189, 32]
Retrieved secret3: [98, 6, 38, 67, 130, 142, 230, 207, 1, 128]
```
