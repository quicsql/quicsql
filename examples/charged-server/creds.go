package main

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

// Fixed DEV credentials. The TLS PKI (CA + client cert) is committed ECDSA P-256
// material (universally interoperable, unlike ed25519 certs which some TLS clients
// reject); the remote-tour embeds the SAME CA cert + client cert. The ed25519
// keyring identity is derived from a seed (both sides compute it identically). All
// of it is DEV ONLY — replace every value for a real deployment.

const (
	devToken    = "quicsql-showcase-dev-token"    // bearer secret
	devUser     = "analyst"                       // HTTP-basic user
	devPassword = "quicsql-showcase-dev-password" // HTTP-basic password
	mtlsCN      = "tourist"                       // client-cert CN → mTLS principal
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

func devSeed(tag string) []byte {
	h := sha256.Sum256([]byte("quicsql-showcase:" + tag))
	return h[:]
}

// devTokenHash is the sha256 of the bearer token, as stored in the auth config.
func devTokenHash() string {
	h := sha256.Sum256([]byte(devToken))
	return hex.EncodeToString(h[:])
}

func devCA() (*x509.Certificate, *ecdsa.PrivateKey) {
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

// devLeaf mints the server's TLS leaf for hosts, signed by the dev CA. The leaf
// key is fresh each start (server-only); the client verifies it against the CA.
func devLeaf(hosts []string) tls.Certificate {
	ca, caKey := devCA()
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

// devAuthLine is the ssh-ed25519 authorized_keys line for the keyring principal.
func devAuthLine() string {
	key := ed25519.NewKeyFromSeed(devSeed("auth"))
	pub, err := ssh.NewPublicKey(key.Public().(ed25519.PublicKey))
	if err != nil {
		panic(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
}

// devVaultKey is the fixed 32-byte Adiantum key for the catalog vault.
func devVaultKey() []byte { return devSeed("vault") }
