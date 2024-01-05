
let alice = Peer(name: "Alice")
let bob = Peer(name: "Bob")

try! alice.deriveSymmetricKey(with: bob.publicKey)
try! bob.deriveSymmetricKey(with: alice.publicKey)

let cypher = ChaChaCypher()
let msg = Payload(message: "aehoo")

let cyphertext = try! alice.encode(msg, using: cypher)

let str = String(data: cyphertext, encoding: .ascii)!
print("\nCyphertext: \(str)")

try! bob.receive(cyphertext, using: cypher)
