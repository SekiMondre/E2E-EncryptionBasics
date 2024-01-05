
let a = Peer()
let b = Peer()

let msg = Payload(message: "aehoo")

try! a.deriveSymmetricKey(with: b.publicKey)
try! b.deriveSymmetricKey(with: a.publicKey)

let ct = try! a.encode(msg)
try! b.receive(ct)
