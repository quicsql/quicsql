package enroll

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"quicsql.net/auth"
	"quicsql.net/authz"
	"quicsql.net/backend"
	"quicsql.net/config"
	"quicsql.net/internal/wire"
	"quicsql.net/meta"
	"quicsql.net/provision"
	"quicsql.net/registry"
	"quicsql.net/secret"
)

// harness wires a real meta store, authenticator, policy, and enrollment
// service behind the auth middleware — the exact production shape.
type harness struct {
	handler http.Handler
	svc     *Service
	policy  *authz.Policy
	seen    *authz.Principal // principal observed by the inner handler
}

func newHarness(t *testing.T, ecfg config.Enroll) *harness {
	t.Helper()
	sec, _ := secret.New(nil)
	store, err := meta.Open(config.MetaStore{Backend: "file", Path: "meta.db"}, sec, t.TempDir(), nil)
	if err != nil {
		t.Fatalf("meta.Open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	authn, err := auth.New(&config.Config{}, sec, nil)
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	policy := authz.NewPolicy(false)
	svc, err := New(ecfg, store, authn, policy, sec, nil)
	if err != nil {
		t.Fatalf("enroll.New: %v", err)
	}
	authn.SetEnrollHandler(svc)
	h := &harness{svc: svc, policy: policy}
	m := authn.Middleware(config.Listener{Name: "l", Auth: []string{"keyring"}}, nil)
	h.handler = m.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.seen = authz.FromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))
	return h
}

func openCfg() config.Enroll {
	return config.Enroll{
		Enabled: true, Policy: "open", MaxPrincipals: 10,
		Grants: []config.EnrollGrant{{DB: "appdb", Level: "read-write"}},
	}
}

func genKey(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
	return priv, line
}

func (h *harness) challenge(t *testing.T) string {
	t.Helper()
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/_auth/challenge", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("challenge status = %d", w.Code)
	}
	var out struct {
		Challenge string `json:"challenge"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return out.Challenge
}

// signedRequest builds method+path signed with priv over a fresh challenge.
func (h *harness) signedRequest(t *testing.T, method, path, body string, priv ed25519.PrivateKey, keyLine string) *http.Request {
	t.Helper()
	chal := h.challenge(t)
	sig := ed25519.Sign(priv, wire.KeyringSigningInput(chal, method, path, ""))
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	r.Header.Set("X-Quicsql-Key", keyLine)
	r.Header.Set("X-Quicsql-Challenge", chal)
	r.Header.Set("X-Quicsql-Signature", base64.StdEncoding.EncodeToString(sig))
	return r
}

func (h *harness) enroll(t *testing.T, priv ed25519.PrivateKey, keyLine, body string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, h.signedRequest(t, http.MethodPost, "/_auth/enroll", body, priv, keyLine))
	return w
}

func TestEnrollOpenPolicyEndToEnd(t *testing.T) {
	h := newHarness(t, openCfg())
	priv, line := genKey(t)

	w := h.enroll(t, priv, line, "")
	if w.Code != http.StatusOK {
		t.Fatalf("enroll status = %d (%s)", w.Code, w.Body.String())
	}
	var out struct {
		Principal string `json:"principal"`
		Created   bool   `json:"created"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if !out.Created || !strings.HasPrefix(out.Principal, "u_") {
		t.Fatalf("enroll response = %+v", out)
	}
	if out.Principal != PrincipalName(line) {
		t.Fatalf("principal name not derived from key: %q", out.Principal)
	}

	// The enrolled key now authenticates like any keyring principal, with the
	// template grants applied.
	w2 := httptest.NewRecorder()
	h.handler.ServeHTTP(w2, h.signedRequest(t, http.MethodPost, "/appdb/query", "", priv, line))
	if w2.Code != http.StatusOK {
		t.Fatalf("authenticated request status = %d", w2.Code)
	}
	if h.seen == nil || h.seen.Name != out.Principal || h.seen.Method != "keyring" {
		t.Fatalf("principal seen by handler = %+v", h.seen)
	}
	if lvl := h.policy.Level(h.seen, "appdb"); lvl != authz.ReadWrite {
		t.Fatalf("template grant level = %v, want read-write", lvl)
	}
	if lvl := h.policy.Level(h.seen, "otherdb"); lvl != authz.None {
		t.Fatalf("non-template db level = %v, want none", lvl)
	}

	// Idempotent re-enroll: same key, same principal, created=false.
	w3 := h.enroll(t, priv, line, "")
	var again struct {
		Principal string `json:"principal"`
		Created   bool   `json:"created"`
	}
	_ = json.Unmarshal(w3.Body.Bytes(), &again)
	if w3.Code != http.StatusOK || again.Created || again.Principal != out.Principal {
		t.Fatalf("re-enroll = %d %+v", w3.Code, again)
	}
}

func TestEnrollRequiresPossession(t *testing.T) {
	h := newHarness(t, openCfg())
	_, line := genKey(t)      // the key we claim
	otherPriv, _ := genKey(t) // the key we actually hold

	w := h.enroll(t, otherPriv, line, "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("enrolling a key we don't hold: status = %d, want 401", w.Code)
	}
}

func TestEnrollTokenPolicy(t *testing.T) {
	cfg := openCfg()
	cfg.Policy = "token"
	sum := sha256.Sum256([]byte("join-code"))
	cfg.Tokens = []string{hex.EncodeToString(sum[:])}
	h := newHarness(t, cfg)
	priv, line := genKey(t)

	if w := h.enroll(t, priv, line, ""); w.Code != http.StatusForbidden {
		t.Fatalf("missing token: status = %d, want 403", w.Code)
	}
	if w := h.enroll(t, priv, line, `{"enroll_token":"wrong"}`); w.Code != http.StatusForbidden {
		t.Fatalf("wrong token: status = %d, want 403", w.Code)
	}
	if w := h.enroll(t, priv, line, `{"enroll_token":"join-code"}`); w.Code != http.StatusOK {
		t.Fatalf("valid token: status = %d", w.Code)
	}
}

func TestEnrollCap(t *testing.T) {
	cfg := openCfg()
	cfg.MaxPrincipals = 1
	h := newHarness(t, cfg)

	p1, l1 := genKey(t)
	if w := h.enroll(t, p1, l1, ""); w.Code != http.StatusOK {
		t.Fatalf("first enroll: %d", w.Code)
	}
	p2, l2 := genKey(t)
	if w := h.enroll(t, p2, l2, ""); w.Code != http.StatusTooManyRequests {
		t.Fatalf("over-cap enroll: status = %d, want 429", w.Code)
	}
	// Idempotent re-enroll of the FIRST key still succeeds at the cap.
	if w := h.enroll(t, p1, l1, ""); w.Code != http.StatusOK {
		t.Fatalf("re-enroll at cap: %d", w.Code)
	}
}

func TestEnrollRateLimitPerIP(t *testing.T) {
	cfg := openCfg()
	cfg.RatePerIP = 0.0001 // effectively no refill within the test
	h := newHarness(t, cfg)
	priv, line := genKey(t)

	// Burst is 3; the 4th immediate attempt from the same IP is refused before
	// any crypto runs.
	codes := make([]int, 0, 4)
	for range 4 {
		codes = append(codes, h.enroll(t, priv, line, "").Code)
	}
	if codes[3] != http.StatusTooManyRequests {
		t.Fatalf("4th attempt = %v, want 429 (codes %v)", codes[3], codes)
	}
}

func TestDeleteRevokesEverything(t *testing.T) {
	h := newHarness(t, openCfg())
	priv, line := genKey(t)
	w := h.enroll(t, priv, line, "")
	var out struct {
		Principal string `json:"principal"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &out)

	existed, err := h.svc.Delete(out.Principal)
	if err != nil || !existed {
		t.Fatalf("delete: existed=%v err=%v", existed, err)
	}
	// The key no longer authenticates…
	w2 := httptest.NewRecorder()
	h.handler.ServeHTTP(w2, h.signedRequest(t, http.MethodPost, "/appdb/query", "", priv, line))
	if w2.Code != http.StatusUnauthorized {
		t.Fatalf("deleted principal still authenticates: %d", w2.Code)
	}
	// …and the grants are gone.
	if lvl := h.policy.Level(&authz.Principal{Name: out.Principal}, "appdb"); lvl != authz.None {
		t.Fatalf("deleted principal keeps level %v", lvl)
	}
	if existed, _ := h.svc.Delete(out.Principal); existed {
		t.Fatal("double delete reported existed")
	}
}

func TestLoadExistingRestoresAcrossRestart(t *testing.T) {
	sec, _ := secret.New(nil)
	dir := t.TempDir()
	store, err := meta.Open(config.MetaStore{Backend: "file", Path: "meta.db"}, sec, dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	priv, line := genKey(t)
	name := PrincipalName(line)
	if err := store.PutEnrolled(name, line); err != nil {
		t.Fatal(err)
	}
	_ = store.Close()

	// "Restart": fresh store handle, fresh authenticator/policy/service.
	store2, err := meta.Open(config.MetaStore{Backend: "file", Path: "meta.db"}, sec, dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer store2.Close()
	authn, _ := auth.New(&config.Config{}, sec, nil)
	policy := authz.NewPolicy(false)
	svc, err := New(openCfg(), store2, authn, policy, sec, nil)
	if err != nil {
		t.Fatal(err)
	}
	n, err := svc.LoadExisting()
	if err != nil || n != 1 {
		t.Fatalf("LoadExisting = %d, %v", n, err)
	}

	m := authn.Middleware(config.Listener{Name: "l", Auth: []string{"keyring"}}, nil)
	var seen *authz.Principal
	handler := m.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = authz.FromContext(r.Context())
	}))
	// Sign a request with the reloaded key.
	cw := httptest.NewRecorder()
	handler.ServeHTTP(cw, httptest.NewRequest(http.MethodGet, "/_auth/challenge", nil))
	var out struct {
		Challenge string `json:"challenge"`
	}
	_ = json.Unmarshal(cw.Body.Bytes(), &out)
	sig := ed25519.Sign(priv, wire.KeyringSigningInput(out.Challenge, "POST", "/appdb/query", ""))
	r := httptest.NewRequest(http.MethodPost, "/appdb/query", nil)
	r.Header.Set("X-Quicsql-Key", line)
	r.Header.Set("X-Quicsql-Challenge", out.Challenge)
	r.Header.Set("X-Quicsql-Signature", base64.StdEncoding.EncodeToString(sig))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusOK || seen == nil || seen.Name != name {
		t.Fatalf("reloaded principal auth: status=%d seen=%+v", w.Code, seen)
	}
	if lvl := policy.Level(seen, "appdb"); lvl != authz.ReadWrite {
		t.Fatalf("reloaded grants level = %v", lvl)
	}
}

func TestPrincipalNameDeterministicAndValid(t *testing.T) {
	_, line := genKey(t)
	a, b := PrincipalName(line), PrincipalName(line)
	if a != b || !strings.HasPrefix(a, "u_") || len(a) != 18 {
		t.Fatalf("PrincipalName: %q / %q", a, b)
	}
}

// provisionHarness is newHarness plus a registry + wired provisioner, so an enroll
// materializes a real per-user database. onRevoke selects the delete policy.
func provisionHarness(t *testing.T, onRevoke string) (*harness, *registry.Registry, *meta.Store) {
	t.Helper()
	dir := t.TempDir()
	sec, _ := secret.New(nil)
	store, err := meta.Open(config.MetaStore{Backend: "file", Path: "meta.db"}, sec, dir, nil)
	if err != nil {
		t.Fatalf("meta.Open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	authn, _ := auth.New(&config.Config{}, sec, nil)
	policy := authz.NewPolicy(false)
	ecfg := config.Enroll{
		Enabled: true, Policy: "open", MaxPrincipals: 10,
		Provision: config.Provision{
			Enabled: true, NameTemplate: "{principal}", Backend: "memory-shared",
			Level: "read-write", OnRevoke: onRevoke,
		},
	}
	svc, err := New(ecfg, store, authn, policy, sec, nil)
	if err != nil {
		t.Fatalf("enroll.New: %v", err)
	}
	authn.SetEnrollHandler(svc)
	reg := registry.New(map[string]backend.Backend{}, nil)
	t.Cleanup(func() { _ = reg.Close() })
	svc.SetProvisioner(provision.New(reg, store, nil, nil, sec, dir, nil))

	h := &harness{svc: svc, policy: policy}
	m := authn.Middleware(config.Listener{Name: "l", Auth: []string{"keyring"}}, nil)
	h.handler = m.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.seen = authz.FromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))
	return h, reg, store
}

// TestEnrollSingleUseCode: a minted code enrolls exactly one new key, then is
// spent; an already-enrolled key still re-enrolls idempotently without any token.
func TestEnrollSingleUseCode(t *testing.T) {
	cfg := config.Enroll{
		Enabled: true, Policy: "token", MaxPrincipals: 10,
		Codes:  config.EnrollCodes{Enabled: true, TTL: time.Hour},
		Grants: []config.EnrollGrant{{DB: "appdb", Level: "read-write"}},
	}
	h := newHarness(t, cfg)

	code, exp, err := h.svc.MintCode()
	if err != nil {
		t.Fatalf("MintCode: %v", err)
	}
	if !strings.HasPrefix(code, "ec_") || exp == 0 {
		t.Fatalf("MintCode returned %q exp=%d", code, exp)
	}
	body := `{"enroll_token":"` + code + `"}`

	priv1, line1 := genKey(t)
	if w := h.enroll(t, priv1, line1, body); w.Code != http.StatusOK {
		t.Fatalf("first enroll with code = %d (%s)", w.Code, w.Body.String())
	}
	// A DIFFERENT key cannot reuse the spent code.
	priv2, line2 := genKey(t)
	if w := h.enroll(t, priv2, line2, body); w.Code != http.StatusForbidden {
		t.Fatalf("reuse of a spent code = %d, want 403", w.Code)
	}
	// A bogus code is refused.
	priv3, line3 := genKey(t)
	if w := h.enroll(t, priv3, line3, `{"enroll_token":"ec_bogus"}`); w.Code != http.StatusForbidden {
		t.Fatalf("bogus code = %d, want 403", w.Code)
	}
	// The first key re-enrolls idempotently with NO token (already trusted).
	if w := h.enroll(t, priv1, line1, ""); w.Code != http.StatusOK {
		t.Fatalf("idempotent re-enroll without token = %d, want 200", w.Code)
	}
}

// TestMintCodeRequiresEnabled: minting fails when codes are off.
func TestMintCodeRequiresEnabled(t *testing.T) {
	cfg := openCfg()
	cfg.Policy = "token"
	cfg.Tokens = []string{"deadbeef"}
	h := newHarness(t, cfg)
	if _, _, err := h.svc.MintCode(); err == nil {
		t.Fatal("MintCode must fail when auth.enroll.codes.enabled is off")
	}
}

// TestEnrollProvisionsPerUserDB: enrolling materializes a per-user database,
// grants the enrollee read-write on it, persists it (so it survives a restart),
// and — with on_revoke: drop — deletes it when the enrollee is removed.
func TestEnrollProvisionsPerUserDB(t *testing.T) {
	h, reg, store := provisionHarness(t, "drop")
	priv, line := genKey(t)

	if w := h.enroll(t, priv, line, ""); w.Code != http.StatusOK {
		t.Fatalf("enroll status = %d (%s)", w.Code, w.Body.String())
	}
	principal := PrincipalName(line)

	// The per-user database is served, and only its owner has access.
	if reg.Backend(principal) == nil {
		t.Fatalf("per-user database %q was not provisioned", principal)
	}
	owner := &authz.Principal{Name: principal, Method: "keyring"}
	if lvl := h.policy.Level(owner, principal); lvl != authz.ReadWrite {
		t.Fatalf("owner grant on own db = %v, want read-write", lvl)
	}
	stranger := &authz.Principal{Name: "u_someoneelse", Method: "keyring"}
	if lvl := h.policy.Level(stranger, principal); lvl != authz.None {
		t.Fatalf("stranger level on another user's db = %v, want none", lvl)
	}

	// It is persisted with its grant, so a restart restores both.
	dbs, _ := store.Databases()
	var persisted *config.Database
	for i := range dbs {
		if dbs[i].Name == principal {
			persisted = &dbs[i]
		}
	}
	if persisted == nil {
		t.Fatalf("per-user database not persisted to the meta store")
	}
	if len(persisted.Grants) != 1 || persisted.Grants[0].Principal != principal {
		t.Fatalf("persisted grant = %+v, want the owner", persisted.Grants)
	}

	// on_revoke: drop — deleting the principal drops the database everywhere.
	if _, err := h.svc.Delete(principal); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if reg.Backend(principal) != nil {
		t.Fatal("on_revoke:drop must remove the database from the registry")
	}
	if dbs, _ := store.Databases(); len(dbs) != 0 {
		t.Fatalf("on_revoke:drop left %d databases in the meta store, want 0", len(dbs))
	}
}

// TestEnrollProvisionKeepsDBByDefault: with on_revoke: keep, deleting the
// enrollee leaves the database in place (data preserved, re-grantable).
func TestEnrollProvisionKeepsDBByDefault(t *testing.T) {
	h, reg, _ := provisionHarness(t, "keep")
	priv, line := genKey(t)
	if w := h.enroll(t, priv, line, ""); w.Code != http.StatusOK {
		t.Fatalf("enroll status = %d (%s)", w.Code, w.Body.String())
	}
	principal := PrincipalName(line)
	if _, err := h.svc.Delete(principal); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if reg.Backend(principal) == nil {
		t.Fatal("on_revoke:keep must leave the database in place")
	}
}
