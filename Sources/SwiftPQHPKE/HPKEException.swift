//
//  Exception.swift
//  SwiftECC
//
//  Created by Leif Ibsen on 18/02/2020.
//

/// The HPKE exceptions
public enum HPKEException: Error, CustomStringConvertible {
    
    /// Textual description of `self`
    public var description: String {
        switch self {
        case .asn1Structure:
            return "ASN1 structure is wrong"
        case .pemStructure:
            return "PEM structure is wrong"
        case .pskError:
            return "Inconsistent PSK parameters"
        case .keyMismatch:
            return "CipherSuite key mismatch"
        case .exportOnlyError:
            return "Export only error"
        case .exportSize:
            return "Export size is negative or too large"
        case .ikmSize:
            return "ikm size is wrong"
        case .cipherTextSize:
            return "Cipher text size is wrong"
        case .publicKeySize:
            return "Public key size is wrong"
        case .privateKeySize:
            return "Private key size is wrong"
        case .publicKeyInconsistent:
            return "Inconsistent public key data"
        case .privateKeyInconsistent:
            return "Inconsistent private key data"
        }
    }
        
    /// ASN1 structure is wrong
    case asn1Structure

    /// PEM structure is wrong
    case pemStructure

    /// Export only error
    case exportOnlyError

    /// Export size is negative or too large
    case exportSize

    /// CipherSuite key mismatch
    case keyMismatch

    /// Inconsistent PSK parameters
    case pskError
    
    /// ikm size is wrong
    case ikmSize
    
    /// Cipher text size is wrong
    case cipherTextSize

    /// Public key size is wrong
    case publicKeySize

    /// Private key size is wrong
    case privateKeySize

    /// Inconsistent public key data
    case publicKeyInconsistent
    
    /// Inconsistent private key data
    case privateKeyInconsistent

}
