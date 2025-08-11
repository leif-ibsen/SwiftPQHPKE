//
//  HPKE.swift
//  SwiftHPKETest
//
//  Created by Leif Ibsen on 19/06/2023.
//

import Foundation
import SwiftKyber

/// Unsigned 8 bit value
public typealias Byte = UInt8

/// Array of unsigned 8 bit values
public typealias Bytes = [UInt8]

public struct CipherSuite: CustomStringConvertible {
    
    static let BASE = Byte(0x00)
    static let PSK = Byte(0x01)
    
    let kind: SwiftKyber.Kind
    let kdfStruct: KDFStruct
    let aeadStruct: AEADStruct
    let suite_id: Bytes
    let Nk: Int
    let Nn: Int
    let Nh: Int
    
    
    // MARK: Initializers
    
    /// Creates a CipherSuite instance
    ///
    /// - Parameters:
    ///   - kem: The key encapsulation mechanism
    ///   - kdf: The key derivation function
    ///   - aead: The AEAD encryption algorithm
    public init(kem: KEM, kdf: KDF, aead: AEAD) {
        var id = Bytes("HPKE".utf8)
        self.kem = kem
        self.kdf = kdf
        self.aead = aead
        switch self.kem {
        case .ML512:
            self.kind = .K512
            id += [0x00, 0x40]
        case .ML768:
            self.kind = .K768
            id += [0x00, 0x41]
        case .ML1024:
            self.kind = .K1024
            id += [0x00, 0x42]
        }
        switch self.kdf {
        case .KDF256:
            id += [0x00, 0x01]
            self.Nh = 32
        case .KDF384:
            id += [0x00, 0x02]
            self.Nh = 48
        case .KDF512:
            id += [0x00, 0x03]
            self.Nh = 64
        }
        switch self.aead {
        case .AESGCM128:
            id += [0x00, 0x01]
            self.Nk = 16
        case .AESGCM256:
            id += [0x00, 0x02]
            self.Nk = 32
        case .CHACHAPOLY:
            id += [0x00, 0x03]
            self.Nk = 32
        case .EXPORTONLY:
            id += [0xff, 0xff]
            self.Nk = 0
        }
        self.Nn = 12
        self.suite_id = id
        self.kdfStruct = KDFStruct(kdf, self.suite_id)
        self.aeadStruct = AEADStruct(aead)
    }
    
    
    // MARK: Stored Properties
    
    /// The key encapsulation mechanism
    public let kem: KEM
    /// The key derivation function
    public let kdf: KDF
    /// The AEAD encryption algorithm
    public let aead: AEAD
    
    
    // MARK: Computed properties
    
    /// A textual representation of `self`
    public var description: String { get { return "(KEM: " + self.kem.description + ", KDF: " + self.kdf.description + ", AEAD: " + self.aead.description + ")"} }
    
    
    // MARK: Instance Methods
    
    /// Derives a public- and private key pair for `self` based on keying material
    ///
    /// - Parameters:
    ///   - ikm: The keying material - 64 bytes
    /// - Returns: The public key and private key pair
    /// - Throws: An exception if the `ikm` size is not 64
    public func deriveKeyPair(ikm: Bytes) throws -> (PublicKey, PrivateKey) {
        guard ikm.count == 64 else {
            throw HPKEException.ikmSize
        }
        do {
            let (encap, decap) = try Kyber.DeriveKeyPair(kind: self.kind, ikm: ikm)
            return (try PublicKey(kem: self.kem, bytes: encap.keyBytes), try PrivateKey(kem: self.kem, bytes: decap.keyBytes))
        } catch {
            fatalError("deriveKeyPair inconsistency")
        }
    }
    
    /// Generates a public- and private key pair for `self`
    ///
    /// - Returns: The public key and private key pair
    public func makeKeyPair() -> (PublicKey, PrivateKey) {
        do {
            return try self.deriveKeyPair(ikm: CipherSuite.randomIKM())
        } catch {
            // Should not happen
            fatalError("makeKeyPair inconsistency")
        }
    }
    
    
    // MARK: Instance Methods - base mode
    
    /// Single-shot encryption in base mode
    ///
    /// - Parameters:
    ///   - publicKey: The recipient public key
    ///   - info: The additional information
    ///   - pt: The plain text to encrypt
    ///   - aad: The associated data
    /// - Returns: The encapsulated key and cipher text
    /// - Throws: An exception if `publicKey` does not match `self` or the encryption fails or `self.aead` is EXPORTONLY
    public func seal(publicKey: PublicKey, info: Bytes, pt: Bytes, aad: Bytes) throws -> (encap: Bytes, ct: Bytes) {
        let sender = try Sender(suite: self, publicKey: publicKey, info: info)
        return (sender.encapsulatedKey, try sender.seal(pt: pt, aad: aad))
    }
    
    /// Single-shot decryption in base mode
    ///
    /// - Parameters:
    ///   - privateKey:The recipient private key
    ///   - info: The additional information
    ///   - ct: The cipher text to decrypt
    ///   - aad: The associated data
    ///   - encap: The encapsulated key
    /// - Returns: The plain text
    /// - Throws: An exception if one of the keys does not match `self` or the decryption fails or `self.aead` is EXPORTONLY
    public func open(privateKey: PrivateKey, info: Bytes, ct: Bytes, aad: Bytes, encap: Bytes) throws -> Bytes {
        let recipient = try Recipient(suite: self, privateKey: privateKey, info: info, encap: encap)
        return try recipient.open(ct: ct, aad: aad)
    }
    
    /// Generate an export secret in base mode
    ///
    /// - Parameters:
    ///   - publicKey: The recipient public key
    ///   - info: The additional information
    ///   - context: The export context
    ///   - L: The length of the export secret
    /// - Returns: The encapsulated key and export secret
    /// - Throws: An exception if `publicKey` does not match `self` or L is negative or too large
    public func sendExport(publicKey: PublicKey, info: Bytes, context: Bytes, L: Int) throws -> (encapsulatedKey: Bytes, secret: Bytes) {
        try self.checkExportSize(L)
        try self.checkPubKey(publicKey)
        let (sharedSecret, encap) = KEMStruct.encap(publicKey)
        let (_, _, exporter_secret) = self.keySchedule(CipherSuite.BASE, sharedSecret, info, [], [])
        return (encap, self.kdfStruct.labeledExpand(exporter_secret, Bytes("sec".utf8), context, L))
    }
    
    /// Retrieve an export secret in base mode
    ///
    /// - Parameters:
    ///   - privateKey: The recipient private key
    ///   - info: The additional information
    ///   - context: The export context
    ///   - L: The length of the export secret
    ///   - encap: The encapsulated key
    /// - Returns: The export secret
    /// - Throws: An exception if one of the keys does not match `self` or L is negative or too large
    public func receiveExport(privateKey: PrivateKey, info: Bytes, context: Bytes, L: Int, encap: Bytes) throws -> Bytes {
        try self.checkExportSize(L)
        try self.checkPrivKey(privateKey)
        let sharedSecret = try KEMStruct.decap(encap, privateKey)
        let (_, _, exporter_secret) = self.keySchedule(CipherSuite.BASE, sharedSecret, info, [], [])
        return self.kdfStruct.labeledExpand(exporter_secret, Bytes("sec".utf8), context, L)
    }
    
    
    // MARK: Instance Methods - preshared key mode
    
    /// Single-shot encryption in preshared key mode
    ///
    /// - Parameters:
    ///   - publicKey: The recipient public key
    ///   - info: The additional information
    ///   - psk: The preshared key
    ///   - pskId: The preshared key id
    ///   - pt: The plain text to encrypt
    ///   - aad: The associated data
    /// - Returns: The encapsulted key and cipher text
    /// - Throws: An exception if `publicKey` does not match `self` or the encryption fails or the `psk` parameters are inconsistent or `self.aead` is EXPORTONLY
    public func seal(publicKey: PublicKey, info: Bytes, psk: Bytes, pskId: Bytes, pt: Bytes, aad: Bytes) throws -> (encap: Bytes, ct: Bytes) {
        let sender = try Sender(suite: self, publicKey: publicKey, info: info, psk: psk, pskId: pskId)
        return (sender.encapsulatedKey, try sender.seal(pt: pt, aad: aad))
    }
    
    /// Single-shot decryption in preshared key mode
    ///
    /// - Parameters:
    ///   - privateKey:The recipient private key
    ///   - info: The additional information
    ///   - psk: The preshared key
    ///   - pskId: The preshared key id
    ///   - ct: The cipher text to decrypt
    ///   - aad: The associated data
    ///   - encap: The encapsulated key
    /// - Returns: The plain text
    /// - Throws: An exception if one of the keys does not match `self` or the decryption fails or the `psk` parameters are inconsistent or `self.aead` is EXPORTONLY
    public func open(privateKey: PrivateKey, info: Bytes, psk: Bytes, pskId: Bytes, ct: Bytes, aad: Bytes, encap: Bytes) throws -> Bytes {
        let recipient = try Recipient(suite: self, privateKey: privateKey, info: info, psk: psk, pskId: pskId, encap: encap)
        return try recipient.open(ct: ct, aad: aad)
    }
    
    /// Generate an export secret in preshared key mode
    ///
    /// - Parameters:
    ///   - publicKey: The recipient public key
    ///   - info: The additional information
    ///   - context: The export context
    ///   - L: The length of the export secret
    ///   - psk: The preshared key
    ///   - pskId: The preshared key id
    /// - Returns: The encapsulated key and export secret
    /// - Throws: An exception if `publicKey` does not match `self` or the `psk` parameters are inconsistent or L is negative or too large
    public func sendExport(publicKey: PublicKey, info: Bytes, context: Bytes, L: Int, psk: Bytes, pskId: Bytes) throws -> (encapsulatedKey: Bytes, secret: Bytes) {
        try self.checkExportSize(L)
        try self.checkPubKey(publicKey)
        let (sharedSecret, encap) = KEMStruct.encap(publicKey)
        let (_, _, exporter_secret) = self.keySchedule(CipherSuite.PSK, sharedSecret, info, psk, pskId)
        return (encap, self.kdfStruct.labeledExpand(exporter_secret, Bytes("sec".utf8), context, L))
    }
    
    /// Retrieve an export secret in preshared key mode
    ///
    /// - Parameters:
    ///   - privateKey: The recipient private key
    ///   - info: The additional information
    ///   - context: The export context
    ///   - L: The length of the export secret
    ///   - psk: The preshared key
    ///   - pskId: The preshared key id
    ///   - encap: The encapsulated key
    /// - Returns: The export secret
    /// - Throws: An exception if one of the keys does not match `self` or the `psk` parameters are inconsistent or L is negative or too large
    public func receiveExport(privateKey: PrivateKey, info: Bytes, context: Bytes, L: Int, psk: Bytes, pskId: Bytes, encap: Bytes) throws -> Bytes {
        try self.checkExportSize(L)
        try self.checkPrivKey(privateKey)
        let sharedSecret = try KEMStruct.decap(encap, privateKey)
        let (_, _, exporter_secret) = self.keySchedule(CipherSuite.PSK, sharedSecret, info, psk, pskId)
        return self.kdfStruct.labeledExpand(exporter_secret, Bytes("sec".utf8), context, L)
    }
    
    
    func keySchedule(_ mode: Byte, _ sharedSecret: Bytes, _ info: Bytes, _ psk: Bytes, _ pskId: Bytes) -> (key: Bytes, base_nonce: Bytes, exporter_secret: Bytes) {
        let psk_id_hash = self.kdfStruct.labeledExtract([], Bytes("psk_id_hash".utf8), pskId)
        let info_hash = self.kdfStruct.labeledExtract([], Bytes("info_hash".utf8), info)
        let key_schedule_context = [mode] + psk_id_hash + info_hash
        let secret = self.kdfStruct.labeledExtract(sharedSecret, Bytes("secret".utf8), psk)
        let key = self.aead == .EXPORTONLY ? [] : self.kdfStruct.labeledExpand(secret, Bytes("key".utf8), key_schedule_context, self.Nk)
        let base_nonce = self.aead == .EXPORTONLY ? [] : self.kdfStruct.labeledExpand(secret, Bytes("base_nonce".utf8), key_schedule_context, self.Nn)
        let exporter_secret = self.kdfStruct.labeledExpand(secret, Bytes("exp".utf8), key_schedule_context, self.Nh)
        return (key, base_nonce, exporter_secret)
    }
    
    func checkExportSize(_ L: Int) throws {
        if L < 0 || L > 255 * self.Nh {
            throw HPKEException.exportSize
        }
    }
    
    func checkPubKey(_ key: PublicKey) throws {
        if self.kem != key.kem {
            throw HPKEException.keyMismatch
        }
    }
    
    func checkPrivKey(_ key: PrivateKey) throws {
        if self.kem != key.kem {
            throw HPKEException.keyMismatch
        }
    }
    
    static func checkPsk(_ psk: Bytes, _ pskId: Bytes) -> Bool {
        return (psk.count == 0 && pskId.count == 0) || (psk.count > 0 && pskId.count > 0)
    }
    
    static func randomIKM() -> Bytes {
        var ikm = Bytes(repeating: 0, count: 64)
        guard SecRandomCopyBytes(kSecRandomDefault, ikm.count, &ikm) == errSecSuccess else {
            fatalError("randomBytes failed")
        }
        return ikm
    }
    
}
