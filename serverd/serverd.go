// Package serverd assembles and runs a quicSQL server from a validated config:
// secrets → meta store → reconcile (config ∪ meta) → backends → registry (warm,
// fail-fast) → sessions → auth/authz → metrics + limiter → HTTP handler →
// transports. It is the single wiring shared by the cmd/quicsql daemon and the
// in-process example/tests, so the assembly lives in one place.
//
// # Composing the engine
//
// The SQLite engine quicSQL exposes is composed by the BINARY, not the wire: what
// extensions, custom functions, and VFS backends the process registers is what
// clients can use, through SQL. A client cannot add or change any of this over
// the network. Register everything BEFORE calling Run:
//
//	import (
//	    _ "quicsql.net/extensions"   // the curated, network-safe bundle
//	    sqlite "gosqlite.org"
//	    "quicsql.net/serverd"
//	)
//
//	func main() {
//	    // Application-defined SQL functions/collations register globally, on every
//	    // connection the server opens. (A client Go closure can never execute in
//	    // this engine — it must be registered here, server-side.)
//	    sqlite.RegisterAutoHook(func(c *sqlite.Conn) error { return myext.Register(c) })
//	    cfg, _ := config.Load("quicsql.yaml")
//	    srv, _ := serverd.Run(cfg, slog.Default())
//	    // …wait, then srv.Shutdown(ctx)
//	}
//
// Per-database storage and connection settings (backend/VFS, pragmas via
// PragmasPreset + Pragmas, grants) live in the config, also server-side.
package serverd

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"quicsql.net/account"
	"quicsql.net/admin"
	"quicsql.net/auth"
	"quicsql.net/authz"
	"quicsql.net/backend"
	"quicsql.net/config"
	"quicsql.net/engine"
	"quicsql.net/enroll"
	"quicsql.net/feed"
	"quicsql.net/httpapi"
	"quicsql.net/limits"
	"quicsql.net/meta"
	"quicsql.net/notify"
	"quicsql.net/obs"
	"quicsql.net/provision"
	"quicsql.net/registry"
	"quicsql.net/secret"
	"quicsql.net/session"
	"quicsql.net/transport"
)

// assurancePolicy maps the configured step-up policy to authz.AssurancePolicy. The
// zero (empty) value resolves to the SECURE default (phishing-resistant); loosening
// an action class to "strong" (accept phishable TOTP) warns loudly at startup.
func assurancePolicy(a config.AssuranceCfg, log *slog.Logger) authz.AssurancePolicy {
	return authz.AssurancePolicy{
		CredentialMgmt: assuranceFactors(a.CredentialMgmt, "credential_mgmt", log),
		Destructive:    assuranceFactors(a.Destructive, "destructive", log),
		StepUpWindow:   a.StepUpWindow,
	}
}

// acctEnrollments adapts the account service to the admin principal-management
// surface (/_admin/principals list + delete). Admin-minted codes don't apply to the
// account model — owners mint attach codes at /_auth/credentials/attach-code.
type acctEnrollments struct{ svc *account.Service }

func (a acctEnrollments) List() ([]meta.Enrolled, error) {
	accts, err := a.svc.List()
	if err != nil {
		return nil, err
	}
	out := make([]meta.Enrolled, len(accts))
	for i, ac := range accts {
		out[i] = meta.Enrolled{Name: ac.Principal, CreatedAt: ac.CreatedAt, LastSeen: ac.LastSeen}
	}
	return out, nil
}

func (a acctEnrollments) Delete(name string) (bool, error) { return a.svc.Delete(name) }

func (a acctEnrollments) MintCode() (string, int64, error) {
	return "", 0, fmt.Errorf("account model: owners mint attach codes at /_auth/credentials/attach-code")
}

func assuranceFactors(v, field string, log *slog.Logger) authz.Factor {
	switch v {
	case "", "phishing_resistant":
		return 0 // AssurancePolicy.withDefaults ⇒ phishing-resistant
	case "strong":
		log.Warn("quicsql: auth.accounts.assurance." + field + " loosened to 'strong' — phishable TOTP can now authorize this action; the secure default is phishing_resistant")
		return authz.PhishingResistant | authz.FactorOTP
	default:
		log.Warn("quicsql: unknown auth.accounts.assurance value — using the secure default", "field", field, "value", v)
		return 0
	}
}

const (
	warmTimeout             = 30 * time.Second
	defaultStatementTimeout = 30 * time.Second
	defaultTxIdleTimeout    = 30 * time.Second
	defaultMaxTxLifetime    = 5 * time.Minute
	reapInterval            = 15 * time.Second
)

// Instance is a running server: its listeners are up and serving. The caller
// owns its lifetime and must call Shutdown to stop it cleanly.
type Instance struct {
	log      *slog.Logger
	servers  *transport.Set
	registry *registry.Registry
	sessions *session.Store
	store    *meta.Store
	reaper   context.CancelFunc

	// Metrics is the live registry, exposed for tests/introspection.
	Metrics *obs.Registry
}

// Servers reports how many listeners are running.
func (in *Instance) Servers() int { return in.servers.Count() }

// Run assembles and starts the server described by cfg. It returns once every
// listener is up (or an error if any stage — a bad seed key, a taken port —
// fails). Seed databases are opened eagerly (fail-fast). The caller drives the
// lifetime and calls Shutdown.
func Run(cfg *config.Config, log *slog.Logger) (*Instance, error) {
	if log == nil {
		log = slog.Default()
	}
	started := time.Now()

	sec, err := secret.New(cfg.Secrets) // eager: all key material resolved at load
	if err != nil {
		return nil, fmt.Errorf("init secrets: %w", err)
	}

	// The slow-query log installs a per-connection profile trace; arm it before any
	// database opens.
	if cfg.Logging.SlowThreshold > 0 {
		backend.InstallSlowLog(cfg.Logging.SlowThreshold, !cfg.Logging.ExpandParams, log)
	}

	var store *meta.Store
	if cfg.ControlPlane.Enabled {
		if store, err = meta.Open(cfg.Server.MetaStore, sec, cfg.Server.DataDir, log); err != nil {
			return nil, fmt.Errorf("open meta store: %w", err)
		}
	}
	dbs, err := reconcile(cfg.Databases, store, cfg.Server.DataDir, log)
	if err != nil {
		closeStore(store, log)
		return nil, fmt.Errorf("reconcile databases: %w", err)
	}
	backends, err := backend.All(dbs, sec, cfg.Server.DataDir)
	if err != nil {
		closeStore(store, log)
		return nil, fmt.Errorf("build backends: %w", err)
	}
	for _, warning := range cfg.Warnings() {
		log.Warn("quicsql: " + warning)
	}

	// The change-feed broker's connection hook must exist BEFORE any database
	// opens (like the security AutoHook), so no writing connection escapes
	// observation. Databases without a stable path can't be observed.
	var broker *feed.Broker
	if cfg.ChangeFeed.Enabled {
		broker = feed.New(cfg.ChangeFeed.Buffer, cfg.ChangeFeed.MaxSubscribers, log)
		broker.Install()
		for name, be := range backends {
			if p, ok := be.(backend.Pather); ok {
				broker.Register(name, p.Path())
			} else {
				log.Warn("quicsql: change feed unavailable (no stable path)", "db", name, "backend", be.Kind())
			}
		}
		log.Info("quicsql: change feed enabled at /<db>/changes", "buffer", cfg.ChangeFeed.Buffer, "max_subscribers", cfg.ChangeFeed.MaxSubscribers)
	}

	reg := registry.New(backends, log)
	warmCtx, warmCancel := context.WithTimeout(context.Background(), warmTimeout)
	if err := reg.Warm(warmCtx); err != nil {
		warmCancel()
		_ = reg.Close()
		closeStore(store, log)
		return nil, fmt.Errorf("open seed databases: %w", err)
	}
	warmCancel()

	reaperCtx, stopReaper := context.WithCancel(context.Background())
	// The daemon defaults both session timeouts HERE (one layer), so they don't get
	// silently overridden by NewStore's own fallbacks — which remain only as a safety
	// net for direct/library callers (e.g. tests).
	sessions, err := session.NewStore(orDefault(cfg.Limits.TxIdleTimeout, defaultTxIdleTimeout), orDefault(cfg.Limits.MaxTxLifetime, defaultMaxTxLifetime), cfg.Limits.MaxSessionsPerDB)
	if err != nil {
		stopReaper()
		_ = reg.Close()
		closeStore(store, log)
		return nil, fmt.Errorf("init sessions: %w", err)
	}
	sessions.StartReaper(reaperCtx, reapInterval)
	// Bound open-handle growth for churned (control-plane-created) databases when
	// idle_handle_timeout is set; a no-op otherwise (handles stay open).
	reg.StartIdleReaper(reaperCtx, reapInterval, cfg.Limits.IdleHandleTimeout)

	authn, err := auth.New(cfg, sec, log)
	if err != nil {
		stopReaper()
		_ = reg.Close()
		closeStore(store, log)
		return nil, fmt.Errorf("init auth: %w", err)
	}
	policy := buildPolicy(cfg, dbs)
	if policy.Open() {
		log.Warn("quicsql: no auth configured — every database is publicly read-write (open mode)")
	}

	metrics := obs.NewRegistry()
	metrics.SetGauge("quicsql_active_sessions", func() int64 { return int64(sessions.Count()) })
	// Sample via reg.List() (which reads the registry map under its mutex), not
	// len(backends): the backends map is shared by reference with the registry and
	// is mutated under that mutex by runtime create/detach, so an unlocked len() here
	// races the control plane during a scrape.
	metrics.SetGauge("quicsql_databases", func() int64 { return int64(len(reg.List())) })
	limiter := limits.New(cfg.Limits.Rate.PerPrincipalRPS, cfg.Limits.MaxConcurrentPerDB)

	eng := engine.New(cfg.Limits.MaxRows, cfg.Limits.MaxResultBytes)
	handlerOpts := []httpapi.Option{
		httpapi.WithLogger(log),
		httpapi.WithMaxBody(cfg.Limits.MaxRequestBytes),
		httpapi.WithMaxBlob(cfg.Limits.MaxBlobBytes),
		httpapi.WithStatementTimeout(orDefault(cfg.Limits.StatementTimeout, defaultStatementTimeout)),
		httpapi.WithSessions(sessions),
		httpapi.WithPolicy(policy),
		httpapi.WithMetrics(metrics),
		httpapi.WithLimiter(limiter),
	}
	// Only override the export cap when configured — WithMaxExport(0) DISABLES the cap
	// (unbounded in-RAM serialize), so an unset value must keep the handler's default.
	if cfg.Limits.MaxExportBytes > 0 {
		handlerOpts = append(handlerOpts, httpapi.WithMaxExport(cfg.Limits.MaxExportBytes))
	}
	if cfg.Auth.SQLPolicy.AllowAttach {
		log.Warn("quicsql: auth.sql_policy.allow_attach is ON — ATTACH/DETACH are permitted for server-admins on interactive sessions, disabling the filesystem sandbox for them. DEV ONLY; do not enable in production")
		if len(cfg.ControlPlane.Admins) == 0 {
			log.Warn("quicsql: auth.sql_policy.allow_attach is ON but control_plane.admins is empty — no principal is a server-admin, so ATTACH stays denied (the switch is inert). Add an admin to use it")
		}
		handlerOpts = append(handlerOpts, httpapi.WithAttach(true, cfg.ControlPlane.Admins))
	}
	if broker != nil {
		handlerOpts = append(handlerOpts, httpapi.WithFeed(broker))
	}
	if cfg.ControlPlane.Enabled {
		adminH := admin.New(reg, policy, store, sessions, sec, metrics, cfg.Server.DataDir, cfg.ControlPlane.Admins, started, log)
		adminH.SetRestoreLimit(cfg.Limits.MaxRestoreBytes)
		// One provisioner materializes/tears down databases for BOTH the control
		// plane's create/detach and self-service enroll-time provisioning, so the
		// ordering-critical sequence lives in exactly one place.
		var pf provision.FeedRegistry
		if broker != nil {
			pf = broker
		}
		prov := provision.New(reg, store, pf, metrics, sec, cfg.Server.DataDir, log)
		adminH.SetProvisioner(prov)
		if cfg.Auth.Enroll.Enabled && !cfg.Auth.Accounts.Enabled {
			// Config validation guarantees the prerequisites here: explicit auth
			// (never open mode) and the control plane (so store is non-nil).
			enr, err := enroll.New(cfg.Auth.Enroll, store, authn, policy, sec, log)
			if err != nil {
				stopReaper()
				sessions.CloseAll()
				_ = reg.Close()
				closeStore(store, log)
				return nil, fmt.Errorf("init enrollment: %w", err)
			}
			if cfg.Auth.Enroll.Provision.Enabled {
				if cfg.Limits.IdleHandleTimeout == 0 {
					log.Warn("quicsql: auth.enroll.provision is on but limits.idle_handle_timeout is unset — every per-user database stays open once first used, so the open-handle set grows with total enrollees; set idle_handle_timeout so idle handles close and the working set tracks ACTIVE users")
				}
				enr.SetProvisioner(prov) // the same provisioner the control plane uses
				log.Info("quicsql: enrollment provisions a per-user database", "backend", cfg.Auth.Enroll.Provision.Backend, "on_revoke", cfg.Auth.Enroll.Provision.OnRevoke)
			}
			n, err := enr.LoadExisting()
			if err != nil {
				stopReaper()
				sessions.CloseAll()
				_ = reg.Close()
				closeStore(store, log)
				return nil, fmt.Errorf("load enrolled principals: %w", err)
			}
			authn.SetEnrollHandler(enr)
			adminH.SetEnrollments(enr)
			if cfg.Auth.Enroll.IdleTTL > 0 {
				authn.SetSeenHook(enr.Touch)
				enr.StartIdleReaper(reaperCtx, reapInterval)
				log.Info("quicsql: enrollment idle GC on", "idle_ttl", cfg.Auth.Enroll.IdleTTL)
			}
			log.Info("quicsql: enrollment enabled at /_auth/enroll", "policy", cfg.Auth.Enroll.Policy, "enrolled", n, "max", cfg.Auth.Enroll.MaxPrincipals)
		}
		if cfg.Auth.Accounts.Enabled {
			ac := cfg.Auth.Accounts
			if ac.Provision.Enabled && cfg.Limits.IdleHandleTimeout == 0 {
				log.Warn("quicsql: auth.accounts.provision is on but limits.idle_handle_timeout is unset — per-account databases stay open once first used; set idle_handle_timeout so the open-handle set tracks ACTIVE accounts, not the total")
			}
			var pwPepper []byte
			if ac.Password.Enabled {
				pwPepper, err = sec.Bytes(ac.Password.Pepper)
				if err != nil {
					stopReaper()
					sessions.CloseAll()
					_ = reg.Close()
					closeStore(store, log)
					return nil, fmt.Errorf("resolve auth.accounts.password.pepper: %w", err)
				}
			}
			acctSvc := account.New(account.Config{
				Provision: ac.Provision, CodeTTL: ac.CodeTTL, RecoveryHold: ac.RecoveryHold,
				IdleTTL: ac.IdleTTL, MaxCredentials: ac.MaxCredentials, MaxAttachCodes: ac.MaxAttachCodes,
				Password: account.PasswordPolicy{Enabled: ac.Password.Enabled, Pepper: pwPepper, MinLength: ac.Password.MinLength},
			}, store, authn, policy, prov, notify.Noop{}, log)
			n, err := acctSvc.LoadExisting()
			if err != nil {
				stopReaper()
				sessions.CloseAll()
				_ = reg.Close()
				closeStore(store, log)
				return nil, fmt.Errorf("load accounts: %w", err)
			}
			acctH := account.NewHandler(acctSvc, authn, assurancePolicy(ac.Assurance, log), ac.RatePerIP, log)
			authn.SetAccountHandler(acctH, acctH.Paths())
			adminH.SetEnrollments(acctEnrollments{acctSvc}) // /_admin/principals list + delete for accounts
			authn.SetSessionStore(store)                    // durable session registry (device list + account-wide revoke)
			if err := store.ClearSessions(); err != nil {   // stale pre-restart rows (their tokens are already dead)
				log.Warn("quicsql: clear stale session registry", "err", err)
			}
			if ac.IdleTTL > 0 {
				authn.SetSeenHook(acctSvc.Touch)
				acctSvc.StartIdleReaper(reaperCtx, reapInterval)
				log.Info("quicsql: account idle GC on", "idle_ttl", ac.IdleTTL)
			}
			log.Info("quicsql: accounts enabled at /_auth/enroll (register/attach), /_auth/{recovery,credentials,sessions}", "accounts", n)
		}
		handlerOpts = append(handlerOpts, httpapi.WithAdmin(adminH))
		log.Info("quicsql: control plane enabled at /_admin", "admins", len(cfg.ControlPlane.Admins))
	}
	handler := httpapi.New(reg, eng, cfg.Routing, handlerOpts...)

	opts := transport.Options{
		Wrap: func(lc config.Listener, h http.Handler) http.Handler {
			return authn.Middleware(lc, log).Wrap(h)
		},
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return auth.NewConnContext(ctx, c)
		},
	}
	servers, err := transport.Serve(log, cfg, handler, opts)
	if err != nil {
		stopReaper()
		sessions.CloseAll()
		_ = reg.Close()
		closeStore(store, log)
		return nil, fmt.Errorf("start listeners: %w", err)
	}
	log.Info("quicsql: ready", "databases", len(backends), "servers", servers.Count())

	return &Instance{
		log: log, servers: servers, registry: reg, sessions: sessions,
		store: store, reaper: stopReaper, Metrics: metrics,
	}, nil
}

// Shutdown stops the listeners (draining in-flight requests within ctx), then
// the sessions (rolling back open transactions and returning connections), then
// the registry (WAL checkpoint on handle close) and the meta store — in that
// order, so nothing closes a resource still in use.
func (in *Instance) Shutdown(ctx context.Context) {
	in.log.Info("quicsql: shutting down")
	in.servers.Shutdown(ctx)
	in.reaper()
	in.sessions.CloseAll()
	if err := in.registry.Close(); err != nil {
		in.log.Error("quicsql: registry close", "err", err)
	}
	closeStore(in.store, in.log)
}

func closeStore(store *meta.Store, log *slog.Logger) {
	if store == nil {
		return
	}
	if err := store.Close(); err != nil {
		log.Error("quicsql: meta store close", "err", err)
	}
}

func orDefault(d, def time.Duration) time.Duration {
	if d <= 0 {
		return def
	}
	return d
}

// buildPolicy compiles the reconciled databases' grants into the authz policy.
func buildPolicy(cfg *config.Config, dbs []config.Database) *authz.Policy {
	configured := len(cfg.Auth.Principals) > 0 || config.AnyGrants(dbs)
	pol := authz.NewPolicy(!configured)
	for _, db := range dbs {
		for _, g := range db.Grants {
			if lvl, ok := authz.ParseLevel(g.Level); ok {
				pol.Grant(db.Name, g.Principal, lvl)
			}
		}
	}
	return pol
}

// reconcile merges the config seed databases with the meta store's
// runtime-created ones (meta wins on a name conflict; a store-less run returns
// the seeds). Meta specs are re-validated — name, backend, and (for on-disk
// backends) path containment within data_dir — so a tampered store can't inject
// a database that never passed the control plane's create-time checks.
func reconcile(seeds []config.Database, store *meta.Store, dataDir string, log *slog.Logger) ([]config.Database, error) {
	if store == nil {
		return seeds, nil
	}
	created, err := store.Databases()
	if err != nil {
		return nil, err
	}
	byName := map[string]config.Database{}
	order := []string{}
	add := func(db config.Database) {
		if _, seen := byName[db.Name]; !seen {
			order = append(order, db.Name)
		}
		byName[db.Name] = db
	}
	for _, db := range seeds {
		add(db)
	}
	for _, db := range created {
		// Full per-database validation (name, backend, mode, tx_lock, pragmas_preset,
		// vault vocabulary) — the same checks a seed and an admin create pass — so a
		// meta entry with e.g. a typo'd mode is skipped rather than silently reopened
		// read-write-create on every restart.
		if err := config.ValidateDatabase(db); err != nil {
			log.Warn("quicsql: skipping invalid meta-store database entry", "db", db.Name, "err", err)
			continue
		}
		// An on-disk backend's path must stay within data_dir, mirroring the
		// control plane's create-time guard: a tampered meta store must not make
		// the daemon open/create a file at an arbitrary absolute or `..` path.
		if config.UsesPath(db.Backend) && db.Path != "" {
			if _, ok := config.WithinDir(dataDir, db.Path); !ok {
				log.Warn("quicsql: skipping meta-store database with out-of-bounds path", "db", db.Name)
				continue
			}
		}
		if _, seen := byName[db.Name]; seen {
			log.Warn("quicsql: meta-store database shadows a config seed", "db", db.Name)
		}
		add(db)
	}
	out := make([]config.Database, 0, len(order))
	for _, name := range order {
		out = append(out, byName[name])
	}
	return out, nil
}
