// Package showcase holds the fixed DEV credentials shared by the charged-server
// and the remote-tour examples. Both derive the IDENTICAL CA / keys / token from
// committed material and seeds, so the two programs interoperate with nothing
// copied between them at runtime. It is DEV-ONLY material — replace every value
// for a real deployment.
package showcase

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Fixed dev identity values, referenced by both sides.
const (
	Token    = "quicsql-showcase-dev-token"    // bearer secret
	User     = "analyst"                       // HTTP-basic user
	Password = "quicsql-showcase-dev-password" // HTTP-basic password
	MTLSCN   = "tourist"                       // client-cert CN → mTLS principal
)

var (
	devNotBefore = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	devNotAfter  = time.Date(2044, 1, 1, 0, 0, 0, 0, time.UTC)
)

// Committed dev CA (ECDSA P-256). The server holds the key to mint its TLS leaf
// and to act as the mTLS client-CA; the client trusts the cert.
const caCertPEM = `-----BEGIN CERTIFICATE-----
MIIBdDCCARugAwIBAgIBATAKBggqhkjOPQQDAjAiMSAwHgYDVQQDExdxdWljc3Fs
LXNob3djYXNlIGRldiBDQTAeFw0yNDAxMDEwMDAwMDBaFw00NDAxMDEwMDAwMDBa
MCIxIDAeBgNVBAMTF3F1aWNzcWwtc2hvd2Nhc2UgZGV2IENBMFkwEwYHKoZIzj0C
AQYIKoZIzj0DAQcDQgAEiAn4p/MveaTBlMpHgBSxAN+bC65p4LJNBvZcwS/RFVZ0
HFRojvbPZHeLS6UzZPoiWqE5MMwa/LsKtEum4W57iKNCMEAwDgYDVR0PAQH/BAQD
AgIEMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFIILcXfbXv88AKcGZygMcWQM
S9RxMAoGCCqGSM49BAMCA0cAMEQCIQCDz5gOZZyQ3i6T7a2kLDRU7uFqT2zqNCaB
UXZIRG5VygIfH+6BFTzNokpwUPlBEjen5CG8z3SXnEmOfN62kHma6g==
-----END CERTIFICATE-----
`

const caKeyPEM = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgRpXWvNs78LfSzNUY
v+a+fwHsG9RcquxdFevMhyoQcSehRANCAASICfin8y95pMGUykeAFLEA35sLrmng
sk0G9lzBL9EVVnQcVGiO9s9kd4tLpTNk+iJaoTkwzBr8uwq0S6bhbnuI
-----END PRIVATE KEY-----
`

// Committed dev client leaf (CN=tourist), signed by the dev CA. Minting a client
// cert needs the CA key (server-only), so the client embeds a pre-minted one.
const clientCertPEM = `-----BEGIN CERTIFICATE-----
MIIBajCCARGgAwIBAgIBAjAKBggqhkjOPQQDAjAiMSAwHgYDVQQDExdxdWljc3Fs
LXNob3djYXNlIGRldiBDQTAeFw0yNDAxMDEwMDAwMDBaFw00NDAxMDEwMDAwMDBa
MBIxEDAOBgNVBAMTB3RvdXJpc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAT+
+bEuVPhHCwhh7GJuUm/78zBdYyJNPTRmfWh1Md53Ebh8AUza5MhCTxg6sbuxppPz
8XqRaUyHIhLtEdvW9sIJo0gwRjAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYI
KwYBBQUHAwIwHwYDVR0jBBgwFoAUggtxd9te/zwApwZnKAxxZAxL1HEwCgYIKoZI
zj0EAwIDRwAwRAIgC9piSBLfPj9030DXzywoIqIuOoVkm85KVahLlqXr2rsCIFi3
Y+hpzmFNE25bhVLdTlu1t2g2Pzy4xnpHnW0YqyBZ
-----END CERTIFICATE-----
`

const clientKeyPEM = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgYOlQ+FrnoHYrQGEu
DZOJzNyXm4b6lPBpU53MtPU1JsChRANCAAT++bEuVPhHCwhh7GJuUm/78zBdYyJN
PTRmfWh1Md53Ebh8AUza5MhCTxg6sbuxppPz8XqRaUyHIhLtEdvW9sIJ
-----END PRIVATE KEY-----
`

// Seed derives a deterministic 32-byte seed for a labeled secret (vault key,
// keyring identity, …). Both sides compute the same value.
func Seed(tag string) []byte {
	h := sha256.Sum256([]byte("quicsql-showcase:" + tag))
	return h[:]
}

// TokenHash is the sha256-hex of the bearer token, as stored in the auth config.
func TokenHash() string {
	h := sha256.Sum256([]byte(Token))
	return hex.EncodeToString(h[:])
}

// VaultKey is the fixed 32-byte Adiantum key for the catalog vault (server side).
func VaultKey() []byte { return Seed("vault") }

// --- server side ---

// CA parses the committed dev CA cert + key (server: mints the TLS leaf and acts
// as the mTLS client-CA).
func CA() (*x509.Certificate, *ecdsa.PrivateKey) {
	cb, _ := pem.Decode([]byte(caCertPEM))
	kb, _ := pem.Decode([]byte(caKeyPEM))
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		panic(err)
	}
	key, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		panic(err)
	}
	return cert, key.(*ecdsa.PrivateKey)
}

// Leaf mints the server's TLS leaf for hosts, signed by the dev CA. The leaf key
// is fresh each start (server-only); the client verifies it against the CA.
func Leaf(hosts []string) tls.Certificate {
	ca, caKey := CA()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject:      pkix.Name{CommonName: "quicsql-showcase server"},
		NotBefore:    devNotBefore,
		NotAfter:     devNotAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		panic(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// AuthLine is the ssh-ed25519 authorized_keys line for the keyring principal
// (server: stored as the "signer" credential).
func AuthLine() string {
	key := ed25519.NewKeyFromSeed(Seed("auth"))
	pub, err := ssh.NewPublicKey(key.Public().(ed25519.PublicKey))
	if err != nil {
		panic(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
}

// --- client side ---

// CAPool is the trust pool for the server's TLS leaf (client side).
func CAPool() *x509.CertPool {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(caCertPEM)) {
		panic("showcase: bad embedded CA cert")
	}
	return pool
}

// ClientCert is the committed mTLS client certificate (CN=tourist), for the
// client's WithClientCert option.
func ClientCert() tls.Certificate {
	cert, err := tls.X509KeyPair([]byte(clientCertPEM), []byte(clientKeyPEM))
	if err != nil {
		panic(err)
	}
	return cert
}

// AuthKey is the ed25519 keyring identity + its authorized_keys line (matches the
// server's AuthLine derivation), for the client's WithEd25519 option.
func AuthKey() (ed25519.PrivateKey, string) {
	key := ed25519.NewKeyFromSeed(Seed("auth"))
	pub, err := ssh.NewPublicKey(key.Public().(ed25519.PublicKey))
	if err != nil {
		panic(err)
	}
	return key, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
}
