import Foundation
import CryptoKit

protocol Cypher {
    func encrypt(_ data: Data, with symmetricKey: SymmetricKey) throws -> Data
    func decrypt(_ ciphertext: Data, with symmetricKey: SymmetricKey) throws -> Data
}

struct ChaChaCypher: Cypher {
    
    func encrypt(_ data: Data, with symmetricKey: SymmetricKey) throws -> Data {
        let sealedBox = try ChaChaPoly.seal(data, using: symmetricKey)
        return sealedBox.combined
    }
    
    func decrypt(_ ciphertext: Data, with symmetricKey: SymmetricKey) throws -> Data {
        let sealedBox = try ChaChaPoly.SealedBox(combined: ciphertext)
        return try ChaChaPoly.open(sealedBox, using: symmetricKey)
    }
}
