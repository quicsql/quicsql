package wire

// KeyringSigningInput is the exact byte string the ed25519 keyring
// challenge/response signs and verifies, shared by the server (auth.tryKeyring)
// and the client (client.authenticate) so the two cannot drift.
//
// The signature binds the server's challenge to the request's method, path, AND
// raw query string. Binding the query means a signature captured off the wire
// cannot be replayed onto a different operation target expressed in the query
// (e.g. a different blob ?id= or ?store=) within the challenge's TTL. The request
// body is deliberately NOT hashed here: bodies stream (a blob write can be
// gigabytes), so neither side can pre-hash them without defeating streaming. The
// residual SQL-body replay vector only exists when the signature is observable —
// i.e. keyring over a cleartext transport — which the server warns loudly about at
// startup (transport.warnCleartextAuth); over TLS the signature never hits the wire.
func KeyringSigningInput(challenge, method, path, rawQuery string) []byte {
	return []byte(challenge + "\n" + method + "\n" + path + "\n" + rawQuery)
}
