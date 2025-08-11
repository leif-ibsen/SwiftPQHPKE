//
//  KeysTest.swift
//  
//
//  Created by Leif Ibsen on 13/08/2023.
//

import XCTest
@testable import SwiftPQHPKE

final class KeysTest: XCTestCase {

    func doTestPEM(_ kem: KEM) throws {
        let suite = CipherSuite(kem: kem, kdf: .KDF256, aead: .AESGCM128)
        let (pubKey, privKey) = suite.makeKeyPair()
        let pubKeyPEM = try PublicKey(pem: pubKey.pem)
        let privKeyPEM = try PrivateKey(pem: privKey.pem)
        XCTAssertEqual(pubKey, pubKeyPEM)
        XCTAssertEqual(privKey, privKeyPEM)
    }

    func testPEM() throws {
        try doTestPEM(.ML512)
        try doTestPEM(.ML768)
        try doTestPEM(.ML1024)
    }

}
