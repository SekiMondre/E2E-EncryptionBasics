import Foundation
import CryptoKit

typealias PrivateKey = Curve25519.KeyAgreement.PrivateKey
typealias PublicKey = Curve25519.KeyAgreement.PublicKey

extension Data {
    
    static func random(count: Int = 32) -> Data {
        var buffer = [UInt8](repeating: 0, count: count)
        let status = SecRandomCopyBytes(kSecRandomDefault, count, &buffer)
        guard status == errSecSuccess else {
            fatalError("Failure generating random bytes with size \(count).")
        }
        return Data(buffer)
    }
    
    var hexString: String {
        self.map { String(format: "%02x", $0) }.joined()
    }
}

extension SymmetricKey {

    var hexString: String {
        withUnsafeBytes { Data($0) }.hexString
    }
}

struct Payload: Codable {
    let message: String
}

struct ErrorMessage: Error {
    let message: String
    
    init(_ message: String) {
        self.message = message
    }
}

class Peer {
    
    let name: String
    
    private let privateKey: PrivateKey
    
    private var symmetricKey: SymmetricKey?
    
    init(name: String) {
        self.name = name
        self.privateKey = PrivateKey()
        print("\(name) private key: \(privateKey.rawRepresentation.hexString)")
        print("\(name) public key: \(privateKey.publicKey.rawRepresentation.hexString)")
    }
    
    var publicKey: PublicKey {
        return privateKey.publicKey
    }
    
    func deriveSymmetricKey(with publicKey: PublicKey) throws {
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
        let sharedKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data(),
            sharedInfo: Data(),
            outputByteCount: 32)
        print("\n\(name) derived the symmetric key:\n\(sharedKey.hexString)")
        self.symmetricKey = sharedKey
    }
    
    func encode<T: Codable>(_ payload: T, using cypher: Cypher) throws -> Data {
        guard let symmetricKey else {
            throw ErrorMessage("No symmetric key found.")
        }
        let payloadData = try JSONEncoder().encode(payload)
        return try cypher.encrypt(payloadData, with: symmetricKey)
    }
    
    func receive(_ cyphertext: Data, using cypher: Cypher) throws {
        guard let symmetricKey else {
            throw ErrorMessage("No symmetric key found.")
        }
        let payloadData = try cypher.decrypt(cyphertext, with: symmetricKey)
        let payload = try JSONDecoder().decode(Payload.self, from: payloadData)
        print("\(name) decoded message: \(payload.message)")
    }
}
