## SwiftPQHPKE

SwiftPQHPKE is based on the Hybrid Public Key Encryption standard as defined in RFC 9180,
which is implemented in the SwiftHPKE package. It differs from the RFC standard and SwiftHPKE in the following ways:

* Its key encapsulation mechanisms are: ML-KEM-512, ML-KEM-768 and ML-KEM-1024 as defined in the FIPS-203 standard, August 13, 2023.
  The corresponding KEM IDs are: 0x0040, 0x0041 and 0x0042.
* It only implements base mode and preshared key mode, not authenticated mode and authenticated preshared key mode.

SwiftPQHPKE requires Swift 5.0. It also requires that the `Int` and `UInt` types be 64 bit types.

Its documentation is build with the DocC plugin and published on GitHub Pages at this location:

https://leif-ibsen.github.io/SwiftPQHPKE/documentation/swiftpqhpke

The documentation is also available in the *SwiftPQHPKE.doccarchive* file.




