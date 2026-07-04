// Package transport starts the quicSQL HTTP handler on every wire — HTTP/1.1,
// cleartext HTTP/2 (h2c), HTTP/2 over TLS, HTTP/3 over QUIC, and Unix sockets —
// all serving the identical http.Handler. TLS certificates come from operator
// files, a dev self-signed generator, or a qip.sh wildcard cert (see qip.go).
package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"

	"quicsql.net/config"
)

// devCertValidity is how long a generated self-signed (dev-only) cert is valid.
const devCertValidity = 365 * 24 * time.Hour

// buildTLS returns a *tls.Config for a profile. forH3 forces TLS 1.3 (HTTP/3
// mandates it; quic-go also enforces this internally, so this is defense in
// depth). The mode is required — an empty mode is an error, so a profile that
// forgot to set it never silently falls back to a throwaway dev cert. A
// client_ca on the profile enables mTLS: requireClient selects whether a client
// certificate is mandatory (mtls is the only auth method) or optional (it sits
// alongside other methods).
func (s *Set) buildTLS(p config.TLSProfile, forH3, requireClient bool) (*tls.Config, error) {
	min, err := tlsMinVersion(p.MinVersion)
	if err != nil {
		return nil, err
	}
	if forH3 {
		min = tls.VersionTLS13
	}
	cfg := &tls.Config{MinVersion: min}
	switch p.Mode {
	case "files":
		cert, err := tls.LoadX509KeyPair(p.Cert, p.Key)
		if err != nil {
			return nil, fmt.Errorf("tls files: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	case "self_signed":
		cert, err := selfSignedCert(p.Hosts)
		if err != nil {
			return nil, err
		}
		cfg.Certificates = []tls.Certificate{cert}
	case "qip":
		// Auto-fetch a qip.sh wildcard cert (a real browser padlock for a private/
		// loopback bind, no CA). Memoized per zone across listeners, with a renewer
		// bound to the Set ctx. See qip.go for the security caveat (public key → not
		// authentication).
		q, err := s.qipCertFor(p)
		if err != nil {
			return nil, err
		}
		cfg.GetCertificate = q.get
	case "":
		return nil, fmt.Errorf("tls mode is required (files | self_signed)")
	default:
		return nil, fmt.Errorf("unknown tls mode %q", p.Mode)
	}
	if p.ClientCA != "" {
		pool, err := clientCAPool(p.ClientCA)
		if err != nil {
			return nil, err
		}
		cfg.ClientCAs = pool
		if requireClient {
			cfg.ClientAuth = tls.RequireAndVerifyClientCert
		} else {
			cfg.ClientAuth = tls.VerifyClientCertIfGiven
		}
	}
	return cfg, nil
}

// clientCAPool loads a PEM bundle of trusted client-certificate authorities for
// mTLS verification.
func clientCAPool(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("tls client_ca: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("tls client_ca %q: no certificates found", path)
	}
	return pool, nil
}

// tlsMinVersion maps the config string to a TLS version, rejecting typos so a
// mistyped floor can't silently downgrade the connection.
func tlsMinVersion(s string) (uint16, error) {
	switch s {
	case "", "1.2":
		return tls.VersionTLS12, nil
	case "1.3":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("invalid tls min_version %q (want 1.2 or 1.3)", s)
	}
}

// selfSignedCert mints an in-memory ECDSA self-signed certificate for dev use,
// covering the given hosts plus loopback.
func selfSignedCert(hosts []string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "quicsql dev"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(devCertValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	if len(tmpl.DNSNames) == 0 {
		tmpl.DNSNames = []string{"localhost"}
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}
