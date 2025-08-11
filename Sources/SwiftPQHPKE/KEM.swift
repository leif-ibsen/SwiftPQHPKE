//
//  KEM.swift
//  SwiftHPKETest
//
//  Created by Leif Ibsen on 22/06/2023.
//

import Foundation

/// The key encapsulation mechanisms
public enum KEM: CustomStringConvertible, CaseIterable {
    
    /// Textual description of `self`
    public var description: String {
        switch self {
        case .ML512:
            return "ML512"
        case .ML768:
            return "ML768"
        case .ML1024:
            return "ML1024"
        }
    }

    /// ML512 - HKDF-SHA256, KEM ID: 0x0040
    case ML512
    /// ML768 - HKDF-SHA384, KEM ID: 0x0041
    case ML768
    /// ML1024 - HKDF-SHA512, KEM ID: 0x0042
    case ML1024
}

struct KEMStruct {
    
    static func encap(_ pkR: PublicKey) -> (sharedSecret: Bytes, enc: Bytes) {
        let (K, ct) = pkR.encapKey.Encapsulate()
        return (K, ct)
    }

    static func decap(_ enc: Bytes, _ skR: PrivateKey) throws -> Bytes {
        return try skR.decapKey.Decapsulate(ct: enc)
    }

}
