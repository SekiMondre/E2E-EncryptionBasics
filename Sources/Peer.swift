import Foundation
import CryptoKit

typealias PrivateKey = Curve25519.KeyAgreement.PrivateKey
typealias PublicKey = Curve25519.KeyAgreement.PublicKey

enum Cypher {
    
    static func encrypt(_ data: Data, with symmetricKey: SymmetricKey) throws -> Data {
        let sealedBox = try ChaChaPoly.seal(data, using: symmetricKey)
        return sealedBox.combined
    }
    
    static func decrypt(_ ciphertext: Data, with symmetricKey: SymmetricKey) throws -> Data {
        let sealedBox = try ChaChaPoly.SealedBox(combined: ciphertext)
        return try ChaChaPoly.open(sealedBox, using: symmetricKey)
    }
}

struct Payload: Codable {
    let message: String
}

class Peer {
    
    private let privateKey: PrivateKey
    
    private var symmetricKey: SymmetricKey?
    
    init() {
        self.privateKey = PrivateKey()
    }
    
    var publicKey: PublicKey {
        return privateKey.publicKey
    }
    
    func deriveSymmetricKey(with publicKey: PublicKey) throws {
        let salt = "salty".data(using: .utf8)!
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
        self.symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(using: SHA256.self, salt: salt, sharedInfo: Data(), outputByteCount: 32)
    }
    
    func encode<T: Codable>(_ payload: T) throws -> Data {
        guard let symmetricKey else {
            fatalError()
        }
        let payloadData = try JSONEncoder().encode(payload)
        let cyphertext = try Cypher.encrypt(payloadData, with: symmetricKey)
        return cyphertext
    }
    
    func receive(_ cyphertext: Data) throws {
        guard let symmetricKey else {
            fatalError()
        }
        let payloadData = try Cypher.decrypt(cyphertext, with: symmetricKey)
        let payload = try JSONDecoder().decode(Payload.self, from: payloadData)
        print("Received message: \(payload.message)")
    }
}
