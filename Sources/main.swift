import Foundation
import CryptoKit

typealias PrivateKey = Curve25519.KeyAgreement.PrivateKey
typealias PublicKey = Curve25519.KeyAgreement.PublicKey

extension Data {
    var hexString: String {
        self.map { String(format: "%02x", $0) }.joined()
    }
}

extension SymmetricKey {
    var hexString: String {
        withUnsafeBytes { Data($0) }.hexString
    }
}

/**
 A cryptographic cipher used to encrypt and decrypt codable payloads.
 */
protocol Cipher {
    func encrypt<T: Codable>(_ payload: T, with symmetricKey: SymmetricKey) throws -> Data
    func decrypt<T: Codable>(_ ciphertext: Data, with symmetricKey: SymmetricKey) throws -> T
}

struct ChaChaCipher: Cipher {
    
    func encrypt<T: Codable>(_ payload: T, with symmetricKey: SymmetricKey) throws -> Data {
        let data = try JSONEncoder().encode(payload)
        let sealedBox = try ChaChaPoly.seal(data, using: symmetricKey)
        return sealedBox.combined
    }
    
    func decrypt<T: Codable>(_ ciphertext: Data, with symmetricKey: SymmetricKey) throws -> T {
        let sealedBox = try ChaChaPoly.SealedBox(combined: ciphertext)
        let data = try ChaChaPoly.open(sealedBox, using: symmetricKey)
        return try JSONDecoder().decode(T.self, from: data)
    }
}

/**
 A class to represent a peer that can take part in a key agreement.
 It holds a private key and can receive a public key from another peer.
 */
class Peer {
    
    let name: String
    
    private let privateKey: PrivateKey
    
    var publicKey: PublicKey { privateKey.publicKey }
    
    private(set) var symmetricKey: SymmetricKey?
    
    init(name: String, privateKey: PrivateKey) {
        self.name = name
        self.privateKey = privateKey
    }
    
    func deriveSymmetricKey(with publicKey: PublicKey) throws {
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
        let sharedKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data(),
            sharedInfo: Data(),
            outputByteCount: 32)
        print("\(name) derived the symmetric key:\n\(sharedKey.hexString)")
        self.symmetricKey = sharedKey
    }
}

/**
 A minimum viable codable payload to be encrypted and sent over from peer to peer.
 */
struct Payload: Codable {
    let message: String
}

// ================================================================================ //
// Basic example of two peers exchanging public keys and sending encrypted messages //
// ================================================================================ //

func makePeer(_ name: String) -> Peer {
    let privateKey = PrivateKey()
    print("\(name) private key: \(privateKey.rawRepresentation.hexString)")
    print("\(name) public key: \(privateKey.publicKey.rawRepresentation.hexString)")
    return Peer(name: name, privateKey: privateKey)
}

let alice = makePeer("Alice")
let bob = makePeer("Bob")

do {
    print("Exchanging keys...")
    try alice.deriveSymmetricKey(with: bob.publicKey)
    try bob.deriveSymmetricKey(with: alice.publicKey)
    
    let payload = Payload(message: "I'm a l33t h4x0r!")
    let cipher = ChaChaCipher()
    
    print("Encoding message: \(payload.message)")
    let ciphertext = try cipher.encrypt(payload, with: alice.symmetricKey!)
    print("Ciphertext: \(String(data: ciphertext, encoding: .ascii)!.debugDescription)")
    
    let decoded: Payload = try cipher.decrypt(ciphertext, with: bob.symmetricKey!)
    print("Decoded message: \(decoded.message)")
} catch {
    print("Error: \(error)")
}
