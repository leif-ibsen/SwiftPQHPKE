//
//  PrivateKey.swift
//  SwiftHPKETest
//
//  Created by Leif Ibsen on 02/07/2023.
//

import ASN1
import Digest
import SwiftKyber

public struct PrivateKey: Equatable, CustomStringConvertible {
    
    let kem: KEM
    let decapKey: DecapsulationKey
    
    // MARK: Initializers
    
    /// Creates a PrivateKey from its type and key bytes
    ///
    /// - Parameters:
    ///   - kem: The key type
    ///   - bytes: The key bytes
    /// - Throws: An exception if `bytes` has wrong size for the key type or are inconsistent
    public init(kem: KEM, bytes: Bytes) throws {
        switch kem {
        case .ML512:
            if bytes.count != 1632 {
                throw HPKEException.privateKeySize
            }
        case .ML768:
            if bytes.count != 2400 {
                throw HPKEException.privateKeySize
            }
        case .ML1024:
            if bytes.count != 3168 {
                throw HPKEException.privateKeySize
            }
        }
        self.kem = kem
        self.decapKey = try DecapsulationKey(keyBytes: bytes)
        self.publicKey = try PublicKey(kem: self.kem, bytes: self.decapKey.encapsulationKey.keyBytes)
    }
    
    /// Creates a PrivateKey from its PEM encoding.
    ///
    /// - Parameters:
    ///   - pem: The PEM encoding of the key
    /// - Throws: An exception if the PEM encoding is wrong
    public init(pem: String) throws {
        let decapKey = try DecapsulationKey(pem: pem)
        if decapKey.keyBytes.count == 1632 {
            try self.init(kem: .ML512, bytes: decapKey.keyBytes)
        } else if decapKey.keyBytes.count == 2400 {
            try self.init(kem: .ML768, bytes: decapKey.keyBytes)
        } else if decapKey.keyBytes.count == 3168 {
            try self.init(kem: .ML1024, bytes: decapKey.keyBytes)
        } else {
            fatalError("PrivateKey PEM inconsistency")
        }
    }
    
    
    // MARK: Stored Properties
    
    /// The corresponding public key
    public internal(set) var publicKey: PublicKey
    
    
    // MARK: Computed Properties
    
    /// The key bytes
    public var bytes: Bytes { get {return self.decapKey.keyBytes} }
    /// The ASN1 encoding of `self`
    public var asn1: ASN1 { get { do { return self.decapKey.asn1 } } }
    /// The PEM encoding of `self.asn1`
    public var pem: String { get { return Base64.pemEncode(self.decapKey.asn1.encode(), "PRIVATE KEY") } }
    /// A textual representation of `self.asn1`
    public var description: String { get { return self.decapKey.description } }
    
}
