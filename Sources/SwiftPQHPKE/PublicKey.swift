//
//  PublicKey.swift
//  SwiftHPKETest
//
//  Created by Leif Ibsen on 02/07/2023.
//

import ASN1
import Digest
import SwiftKyber

public struct PublicKey: Equatable, CustomStringConvertible {
    
    let kem: KEM
    let encapKey: EncapsulationKey


    // MARK: Initializers
        
    /// Creates a PublicKey from its type and key bytes.
    ///
    /// - Parameters:
    ///   - kem: The key type
    ///   - bytes: The key bytes
    /// - Throws: An exception if `bytes` has wrong size for the key type or are inconsistent
    public init(kem: KEM, bytes: Bytes) throws {
        switch kem {
        case .ML512:
            if bytes.count != 800 {
                throw HPKEException.publicKeySize
            }
        case .ML768:
            if bytes.count != 1184 {
                throw HPKEException.publicKeySize
            }
        case .ML1024:
            if bytes.count != 1568 {
                throw HPKEException.publicKeySize
            }
        }
        self.kem = kem
        self.encapKey = try EncapsulationKey(keyBytes: bytes)
    }

    /// Creates a PublicKey from its PEM encoding
    ///
    /// - Parameters:
    ///   - pem: The PEM encoding of the key
    /// - Throws: An exception if the PEM encoding is wrong
    public init(pem: String) throws {
        let encapKey = try EncapsulationKey(pem: pem)
        if encapKey.keyBytes.count == 800 {
            try self.init(kem: .ML512, bytes: encapKey.keyBytes)
        } else if encapKey.keyBytes.count == 1184 {
            try self.init(kem: .ML768, bytes: encapKey.keyBytes)
        } else if encapKey.keyBytes.count == 1568 {
            try self.init(kem: .ML1024, bytes: encapKey.keyBytes)
        } else {
            fatalError("PublicKey PEM inconsistency")
        }
    }


    // MARK: Computed Properties

    /// The key bytes
    public var bytes: Bytes { get {return self.encapKey.keyBytes} }
    /// The ASN1 encoding of `self`
    public var asn1: ASN1 { get { do { return self.encapKey.asn1 } } }
    /// The PEM encoding of `self.asn1`
    public var pem: String { get { return Base64.pemEncode(self.encapKey.asn1.encode(), "PUBLIC KEY") } }
    /// A textual representation of `self.asn1`
    public var description: String { get { return self.encapKey.description } }

}
