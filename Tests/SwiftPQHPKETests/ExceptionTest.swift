//
//  TestHPKEExceptions.swift
//  
//
//  Created by Leif Ibsen on 10/07/2023.
//

import XCTest
@testable import SwiftPQHPKE
import SwiftKyber

final class HPKEExceptionTest: XCTestCase {

    func testIkmSize() throws {
        let ikm = Bytes(repeating: 1, count: 65)
        do {
            let _ = try CipherSuite(kem: .ML512, kdf: .KDF256, aead: .AESGCM128).deriveKeyPair(ikm: ikm)
            XCTFail("Expected ikmSize exception")
        } catch HPKEException.ikmSize {
        } catch {
            XCTFail("Expected ikmSize exception")
        }
    }

    func testPublicKeySize() throws {
        let keyBytes = Bytes(repeating: 1, count: 16)
        do {
            let _ = try PublicKey(kem: .ML512, bytes: keyBytes)
            XCTFail("Expected publicKeySize exception")
        } catch HPKEException.publicKeySize {
        } catch {
            XCTFail("Expected publicKeySize exception")
        }
    }

    func testPrivateKeySize() throws {
        let keyBytes = Bytes(repeating: 1, count: 16)
        do {
            let _ = try PrivateKey(kem: .ML512, bytes: keyBytes)
            XCTFail("Expected privateKeySize exception")
        } catch HPKEException.privateKeySize {
        } catch {
            XCTFail("Expected privateKeySize exception")
        }
    }
    
    func testKeyMismatch() throws {
        let suite512 = CipherSuite(kem: .ML512, kdf: .KDF256, aead: .AESGCM128)
        let suite768 = CipherSuite(kem: .ML768, kdf: .KDF256, aead: .AESGCM128)
        do {
            let (pub768, _) = suite768.makeKeyPair()
            let _ = try Sender(suite: suite512, publicKey: pub768, info: [])
            XCTFail("Expected keyMismatch exception")
        } catch HPKEException.keyMismatch {
        } catch {
            XCTFail("Expected keyMismatch exception")
        }
    }

    func testEncapMismatch() throws {
        let suite768 = CipherSuite(kem: .ML768, kdf: .KDF384, aead: .CHACHAPOLY)
        let suite1024 = CipherSuite(kem: .ML1024, kdf: .KDF512, aead: .CHACHAPOLY)
        let (_, recipientPriv768) = suite768.makeKeyPair()
        let (recipientPub1024, _) = suite1024.makeKeyPair()
        let sender1024 = try Sender(suite: suite1024, publicKey: recipientPub1024, info: [])
        do {
            _ = try Recipient(suite: suite768, privateKey: recipientPriv768, info: [], encap: sender1024.encapsulatedKey)
            XCTFail("Expected cipherTextSize exception")
        } catch Exception.cipherTextSize {
        } catch {
            XCTFail("Expected cipherTextSize exception")
        }
    }

    func testExportOnly() throws {
        let suite = CipherSuite(kem: .ML512, kdf: .KDF256, aead: .EXPORTONLY)
        do {
            let (pub, _) = suite.makeKeyPair()
            let _ = try suite.seal(publicKey: pub, info: [], pt: [], aad: [])
            XCTFail("Expected exportOnlyError exception")
        } catch HPKEException.exportOnlyError {
        } catch {
            XCTFail("Expected exportOnlyError exception")
        }
    }

    func doTestExportSize(_ kdf: KDF, _ kdfSize: Int) throws {
        let suite = CipherSuite(kem: .ML512, kdf: kdf, aead: .CHACHAPOLY)
        let (pub, _) = suite.makeKeyPair()
        do {
            let _ = try suite.sendExport(publicKey: pub, info: [], context: [], L: 0)
        } catch {
            XCTFail("Did not expect exception")
        }
        do {
            let _ = try suite.sendExport(publicKey: pub, info: [], context: [], L: kdfSize * 255)
        } catch {
            XCTFail("Did not expect exception")
        }
        do {
            let _ = try suite.sendExport(publicKey: pub, info: [], context: [], L: -1)
            XCTFail("Expected exportSize exception")
        } catch HPKEException.exportSize {
        } catch {
            XCTFail("Expected exportSize exception")
        }
        do {
            let _ = try suite.sendExport(publicKey: pub, info: [], context: [], L: kdfSize * 255 + 1)
            XCTFail("Expected exportSize exception")
        } catch HPKEException.exportSize {
        } catch {
            XCTFail("Expected exportSize exception")
        }
    }

    func testExportSize() throws {
        try doTestExportSize(.KDF256, 32)
        try doTestExportSize(.KDF384, 48)
        try doTestExportSize(.KDF512, 64)
    }

}
