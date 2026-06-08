package auth

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"

	"gosqlite.org/server/config"
	"gosqlite.org/server/secret"
)

// build compiles an Authenticator over the given principals with no secret
// sources (so credential params are literals) and returns a Middleware that
// accepts every method.
func build(t *testing.T, principals ...config.Principal) *Middleware {
	t.Helper()
	sec, _ := secret.New(nil)
	cfg := &config.Config{Auth: config.Auth{Principals: principals}}
	a, err := New(cfg, sec, nil)
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	lc := config.Listener{Name: "l", Auth: []string{"none", "peercred", "bearer", "password", "mtls", "keyring"}}
	return a.Middleware(lc, nil)
}

func principal(name, method string, params map[string]any) config.Principal {
	return config.Principal{Name: name, Methods: []map[string]any{{method: params}}}
}

func TestBearerAuth(t *testing.T) {
	sum := sha256.Sum256([]byte("s3cr3t"))
	m := build(t, principal("app", "bearer", map[string]any{"token_hash": hex.EncodeToString(sum[:])}))

	r := httptest.NewRequest(http.MethodPost, "/app/query", nil)
	r.Header.Set("Authorization", "Bearer s3cr3t")
	p, err := m.authenticate(r)
	if err != nil || p.Name != "app" || p.Method != "bearer" {
		t.Fatalf("valid bearer: p=%+v err=%v", p, err)
	}

	bad := httptest.NewRequest(http.MethodPost, "/app/query", nil)
	bad.Header.Set("Authorization", "Bearer wrong")
	if _, err := m.authenticate(bad); err == nil {
		t.Fatal("wrong bearer token must be rejected")
	}
}

func TestPasswordAuth(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("hunter2"), bcrypt.MinCost)
	m := build(t, principal("analyst", "password", map[string]any{"user": "analyst", "password_hash": string(hash)}))

	r := httptest.NewRequest(http.MethodPost, "/x/query", nil)
	r.SetBasicAuth("analyst", "hunter2")
	p, err := m.authenticate(r)
	if err != nil || p.Name != "analyst" || p.Method != "password" {
		t.Fatalf("valid password: p=%+v err=%v", p, err)
	}

	bad := httptest.NewRequest(http.MethodPost, "/x/query", nil)
	bad.SetBasicAuth("analyst", "nope")
	if _, err := m.authenticate(bad); err == nil {
		t.Fatal("wrong password must be rejected")
	}
	unknown := httptest.NewRequest(http.MethodPost, "/x/query", nil)
	unknown.SetBasicAuth("ghost", "hunter2")
	if _, err := m.authenticate(unknown); err == nil {
		t.Fatal("unknown user must be rejected")
	}
}

func TestMTLSAuth(t *testing.T) {
	cert := makeCert(t, "ops.example.com")
	m := build(t, principal("ops", "mtls", map[string]any{"subject_cn": "ops.example.com"}))

	r := httptest.NewRequest(http.MethodPost, "/x/query", nil)
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	p, err := m.authenticate(r)
	if err != nil || p.Name != "ops" || p.Method != "mtls" {
		t.Fatalf("valid mtls: p=%+v err=%v", p, err)
	}

	other := makeCert(t, "intruder.example.com")
	bad := httptest.NewRequest(http.MethodPost, "/x/query", nil)
	bad.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{other}}
	if _, err := m.authenticate(bad); err == nil {
		t.Fatal("unmapped client cert must be rejected")
	}
}

func TestMTLSBySPKI(t *testing.T) {
	cert := makeCert(t, "no-cn-match")
	spki := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	m := build(t, principal("node", "mtls", map[string]any{"spki_sha256": hex.EncodeToString(spki[:])}))
	r := httptest.NewRequest(http.MethodPost, "/x/query", nil)
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	p, err := m.authenticate(r)
	if err != nil || p.Name != "node" {
		t.Fatalf("spki match: p=%+v err=%v", p, err)
	}
}

func TestKeyringChallengeResponse(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	keyLine := authorizedKeyLine(t, pub)
	m := build(t, principal("signer", "keyring", map[string]any{"ed25519": keyLine}))

	chal, err := m.a.challenger.mint()
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	sig := ed25519.Sign(priv, []byte(chal))

	r := httptest.NewRequest(http.MethodPost, "/x/query", nil)
	r.Header.Set("X-Quicsql-Key", keyLine)
	r.Header.Set("X-Quicsql-Challenge", chal)
	r.Header.Set("X-Quicsql-Signature", base64.StdEncoding.EncodeToString(sig))
	p, err := m.authenticate(r)
	if err != nil || p.Name != "signer" || p.Method != "keyring" {
		t.Fatalf("valid keyring: p=%+v err=%v", p, err)
	}

	// A signature over a different challenge (or a forged one) is rejected.
	forged := httptest.NewRequest(http.MethodPost, "/x/query", nil)
	forged.Header.Set("X-Quicsql-Key", keyLine)
	forged.Header.Set("X-Quicsql-Challenge", chal)
	forged.Header.Set("X-Quicsql-Signature", base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte("other"))))
	if _, err := m.authenticate(forged); err == nil {
		t.Fatal("signature over the wrong message must be rejected")
	}

	// An unmintable (forged) challenge is rejected even with a valid signature.
	badChal := httptest.NewRequest(http.MethodPost, "/x/query", nil)
	badChal.Header.Set("X-Quicsql-Key", keyLine)
	badChal.Header.Set("X-Quicsql-Challenge", "AAAAAAAAAAAAAAAAAAAAAA")
	badChal.Header.Set("X-Quicsql-Signature", base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte("AAAAAAAAAAAAAAAAAAAAAA"))))
	if _, err := m.authenticate(badChal); err == nil {
		t.Fatal("a challenge we did not mint must be rejected")
	}

	// A stranger's key (not in the roster) is rejected.
	_, strangerPriv, _ := ed25519.GenerateKey(rand.Reader)
	strangerPub := ed25519.PublicKey(strangerPriv.Public().(ed25519.PublicKey))
	strangerLine := authorizedKeyLine(t, strangerPub)
	unknown := httptest.NewRequest(http.MethodPost, "/x/query", nil)
	unknown.Header.Set("X-Quicsql-Key", strangerLine)
	unknown.Header.Set("X-Quicsql-Challenge", chal)
	unknown.Header.Set("X-Quicsql-Signature", base64.StdEncoding.EncodeToString(ed25519.Sign(strangerPriv, []byte(chal))))
	if _, err := m.authenticate(unknown); err == nil {
		t.Fatal("a key outside the roster must be rejected")
	}
}

func TestNoneFallbackAndRequired(t *testing.T) {
	// A no-credential request on a none-accepting listener is anonymous.
	m := build(t) // accepts none among others
	p, err := m.authenticate(httptest.NewRequest(http.MethodPost, "/x/query", nil))
	if err != nil || !p.IsAnonymous() {
		t.Fatalf("no-cred none: p=%+v err=%v", p, err)
	}

	// A listener that does NOT accept none rejects a no-credential request.
	sec, _ := secret.New(nil)
	a, _ := New(&config.Config{}, sec, nil)
	strict := a.Middleware(config.Listener{Name: "s", Auth: []string{"bearer"}}, nil)
	if _, err := strict.authenticate(httptest.NewRequest(http.MethodPost, "/x/query", nil)); err == nil {
		t.Fatal("a bearer-only listener must reject an unauthenticated request")
	}
}

func TestChallengeEndpointAndHealthPublic(t *testing.T) {
	sec, _ := secret.New(nil)
	a, _ := New(&config.Config{}, sec, nil)
	m := a.Middleware(config.Listener{Name: "s", Auth: []string{"bearer", "keyring"}}, nil) // no `none`
	sentinel := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
	h := m.Wrap(sentinel)

	// /_auth/challenge is public (keyring is accepted) and returns a challenge
	// even without credentials.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/_auth/challenge", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("challenge endpoint: status %d", rec.Code)
	}
	// /_health is public too (reaches the inner handler as anonymous).
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/_health", nil))
	if rec.Code != http.StatusTeapot {
		t.Fatalf("health should reach inner handler: status %d", rec.Code)
	}
	// A data path with no credential is blocked (401) on a none-less listener.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/db/query", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated data path: status %d, want 401", rec.Code)
	}
}

// --- helpers ---

func makeCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert
}

func authorizedKeyLine(t *testing.T, pub ed25519.PublicKey) string {
	t.Helper()
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("ssh pub: %v", err)
	}
	return string(ssh.MarshalAuthorizedKey(sshPub))
}
