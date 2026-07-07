package serverd

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"quicsql.net/admin"
	"quicsql.net/auth"
	"quicsql.net/authz"
	"quicsql.net/config"
	"quicsql.net/meta"
	"quicsql.net/provision"
	"quicsql.net/secret"
)

// Closer is an optional shutdown hook a Feature returns from Setup; Shutdown closes
// it once. A tiny interface so core serverd never names a feature's concrete types
// (e.g. a feature module's notifier outbox), which aren't compiled into core.
type Closer interface{ Close() }

// Host gives a Feature access to the core services it wires against during Run. It
// exposes CORE types only — a Feature lives in its OWN module (e.g. the accounts
// product) that imports quicSQL as a dependency, so this is the stable seam between
// them (the Caddy `caddy.Context` / CoreDNS controller analogue). Features are wired
// during the control-plane phase, so Admin() is non-nil.
type Host interface {
	Config() *config.Config
	Secrets() secret.Resolver
	Meta() *meta.Store
	Authenticator() *auth.Authenticator
	Policy() *authz.Policy
	Provisioner() *provision.Provisioner
	Admin() *admin.Handler
	// ReaperContext is cancelled at Shutdown — use it for the feature's background upkeep.
	ReaperContext() context.Context
	ReapInterval() time.Duration
	Logger() *slog.Logger
}

// Feature is an optional server module compiled into a PRODUCT binary (not the core
// `quicsql` binary) and registered via RegisterFeature — the Caddy/CoreDNS plugin
// model. During Run, after the core is built and before the listeners start, Setup
// wires the feature against Host and returns an optional Closer (closed at Shutdown).
// A Feature reads its own config section to decide whether it is active.
type Feature interface {
	// Name identifies the feature in logs and errors (e.g. "accounts").
	Name() string
	// Setup wires the feature against the host; the returned Closer (may be nil) is
	// closed at shutdown. An error aborts Run and tears the half-built server down.
	Setup(Host) (Closer, error)
}

var (
	featuresMu sync.Mutex
	features   []Feature
)

// RegisterFeature adds an optional feature module to every server started by Run.
// Call it from an init() in the feature's package; a product binary compiles the
// feature in with a blank import. The core `cmd/quicsql` binary registers none.
func RegisterFeature(f Feature) {
	featuresMu.Lock()
	defer featuresMu.Unlock()
	features = append(features, f)
}

func registeredFeatures() []Feature {
	featuresMu.Lock()
	defer featuresMu.Unlock()
	return append([]Feature(nil), features...)
}

// featureHost is the concrete Host handed to each Feature during Run.
type featureHost struct {
	cfg          *config.Config
	sec          secret.Resolver
	store        *meta.Store
	authn        *auth.Authenticator
	policy       *authz.Policy
	prov         *provision.Provisioner
	adminH       *admin.Handler
	reaperCtx    context.Context
	reapInterval time.Duration
	log          *slog.Logger
}

func (h *featureHost) Config() *config.Config              { return h.cfg }
func (h *featureHost) Secrets() secret.Resolver            { return h.sec }
func (h *featureHost) Meta() *meta.Store                   { return h.store }
func (h *featureHost) Authenticator() *auth.Authenticator  { return h.authn }
func (h *featureHost) Policy() *authz.Policy               { return h.policy }
func (h *featureHost) Provisioner() *provision.Provisioner { return h.prov }
func (h *featureHost) Admin() *admin.Handler               { return h.adminH }
func (h *featureHost) ReaperContext() context.Context      { return h.reaperCtx }
func (h *featureHost) ReapInterval() time.Duration         { return h.reapInterval }
func (h *featureHost) Logger() *slog.Logger                { return h.log }
