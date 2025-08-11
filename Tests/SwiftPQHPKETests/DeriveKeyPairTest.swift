//
//  DeriveKeyPairTest.swift
//  SwiftPQHPKE
//
//  Created by Leif Ibsen on 04/08/2025.
//

import XCTest
@testable import SwiftPQHPKE
import SwiftKyber

final class DeriveKeyPairTest: XCTestCase {

    func doTest(_ kem: KEM, _ kind: SwiftKyber.Kind) throws {
        let suite = CipherSuite(kem: kem, kdf: .KDF256, aead: .AESGCM128)
        for _ in 0 ..< 10 {
            let ikm = CipherSuite.randomIKM()
            let (pubKey, privKey) = try suite.deriveKeyPair(ikm: ikm)
            let (encap, decap) = try Kyber.DeriveKeyPair(kind: kind, ikm: ikm)
            XCTAssertEqual(pubKey.encapKey, encap)
            XCTAssertEqual(privKey.decapKey, decap)
        }
    }

    func test512() throws {
        try doTest(.ML512, .K512)
    }

    func test768() throws {
        try doTest(.ML768, .K768)
    }

    func test1024() throws {
        try doTest(.ML1024, .K1024)
    }

}
