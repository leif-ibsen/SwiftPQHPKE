//
//  CipherSuiteTest.swift
//  
//
//  Created by Leif Ibsen on 18/08/2023.
//

import XCTest
@testable import SwiftPQHPKE

final class CipherSuiteTest: XCTestCase {
    
    var plainText: Bytes = []
    var theContext: Bytes = []
    var theInfo: Bytes = []
    var thePsk: Bytes = []
    var thePskId: Bytes = []
    var theAad: Bytes = []
    var length = 0
    
    func doBaseMode(_ suite: CipherSuite, _ recipientPub: PublicKey, _ recipientPriv: PrivateKey) throws {
        let (encap, ct) = try suite.seal(publicKey: recipientPub, info: theInfo, pt: plainText, aad: theAad)
        let pt = try suite.open(privateKey: recipientPriv, info: theInfo, ct: ct, aad: theAad, encap: encap)
        XCTAssertEqual(plainText, pt)
    }
    
    func doBaseSecret(_ suite: CipherSuite, _ recipientPub: PublicKey, _ recipientPriv: PrivateKey) throws {
        let (encap, secret) = try suite.sendExport(publicKey: recipientPub, info: theInfo, context: theContext, L: length)
        let secretx = try suite.receiveExport(privateKey: recipientPriv, info: theInfo, context: theContext, L: length, encap: encap)
        XCTAssertEqual(secret, secretx)
    }
    
    func doPskMode(_ suite: CipherSuite, _ recipientPub: PublicKey, _ recipientPriv: PrivateKey) throws {
        let (encap, ct) = try suite.seal(publicKey: recipientPub, info: theInfo, psk: thePsk, pskId: thePskId, pt: plainText, aad: theAad)
        let pt = try suite.open(privateKey: recipientPriv, info: theInfo, psk: thePsk, pskId: thePskId, ct: ct, aad: theAad, encap: encap)
        XCTAssertEqual(plainText, pt)
    }
    
    func doPskSecret(_ suite: CipherSuite, _ recipientPub: PublicKey, _ recipientPriv: PrivateKey) throws {
        let (encap, secret) = try suite.sendExport(publicKey: recipientPub, info: theInfo, context: theContext, L: length, psk: thePsk, pskId: thePskId)
        let secretx = try suite.receiveExport(privateKey: recipientPriv, info: theInfo, context: theContext, L: length, psk: thePsk, pskId: thePskId, encap: encap)
        XCTAssertEqual(secret, secretx)
    }

    func doTest() throws {

        // Test all combinations of KEM, KDF and AEAD in both modes

        for kem in KEM.allCases {
            for kdf in KDF.allCases {
                for aead in AEAD.allCases {
                    let suite = CipherSuite(kem: kem, kdf: kdf, aead: aead)
                    let (recipientPub, recipientPriv) = suite.makeKeyPair()
                    if aead != .EXPORTONLY {
                        try doBaseMode(suite, recipientPub, recipientPriv)
                        try doPskMode(suite, recipientPub, recipientPriv)
                    }
                    try doBaseSecret(suite, recipientPub, recipientPriv)
                    try doPskSecret(suite, recipientPub, recipientPriv)
                }
            }
        }
    }

    func testCipherSuite1() throws {

        // Test with non-empty parameters

        plainText = Bytes("This is the plaintext".utf8)
        theContext = [1, 2, 3]
        theInfo = [4, 5, 6]
        thePsk = [7, 8, 9]
        thePskId = [10, 11, 12]
        theAad = [13, 14, 15]
        length = 10

        try doTest()
    }
    
    func testCipherSuite2() throws {

        // Test with empty parameters

        plainText = []
        theContext = []
        theInfo = []
        thePsk = []
        thePskId = []
        theAad = []
        length = 0

        try doTest()
    }
    
}
