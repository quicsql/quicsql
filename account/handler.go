package account

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"

	"quicsql.net/auth"
	"quicsql.net/authz"
	"quicsql.net/internal/httpjson"
)

// maxBody bounds an account request body (codes/secrets only).
const maxBody = 4 << 10

// Handler serves the account HTTP endpoints under /_auth. The join/recover paths do
// their own auth (possession proof / secret redeem); the management paths resolve
// the caller's session themselves and gate on assurance.
type Handler struct {
	svc       *Service
	authn     *auth.Authenticator
	assurance authz.AssurancePolicy
	limiter   *ipLimiter
	log       *slog.Logger
}

// NewHandler wires the account HTTP layer. ratePerIP throttles the unauthenticated
// join/recover endpoints (<=0 disables it).
func NewHandler(svc *Service, authn *auth.Authenticator, assurance authz.AssurancePolicy, ratePerIP float64, log *slog.Logger) *Handler {
	if log == nil {
		log = slog.Default()
	}
	return &Handler{svc: svc, authn: authn, assurance: assurance, limiter: newIPLimiter(ratePerIP), log: log}
}

// ServeHTTP dispatches by path.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/_auth/enroll":
		h.registerOrAttach(w, r)
	case "/_auth/login":
		h.login(w, r)
	case "/_auth/password":
		h.password(w, r)
	case "/_auth/recovery/redeem":
		h.recover(w, r)
	case "/_auth/credentials":
		h.listCredentials(w, r)
	case "/_auth/credentials/attach-code":
		h.attachCode(w, r)
	case "/_auth/credentials/delete":
		h.detach(w, r)
	case "/_auth/sessions":
		h.listSessions(w, r)
	case "/_auth/sessions/revoke":
		h.revokeSessions(w, r)
	default:
		httpjson.Error(w, http.StatusNotFound, "unknown account endpoint")
	}
}

// Paths this handler owns — serverd mounts the join/recover ones pre-auth and the
// rest post-auth (both dispatch back here).
func (h *Handler) Paths() []string {
	return []string{
		"/_auth/enroll", "/_auth/login", "/_auth/password", "/_auth/recovery/redeem",
		"/_auth/credentials", "/_auth/credentials/attach-code", "/_auth/credentials/delete",
		"/_auth/sessions", "/_auth/sessions/revoke",
	}
}

// --- join: register or attach (pre-auth, possession proof) ------------------

func (h *Handler) registerOrAttach(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpjson.Error(w, http.StatusMethodNotAllowed, "use POST")
		return
	}
	if !h.limiter.allow(remoteIP(r)) {
		httpjson.Error(w, http.StatusTooManyRequests, "rate limited")
		return
	}
	var body struct {
		Token string `json:"enroll_token"` // an attach code ⇒ attach; empty ⇒ register
	}
	readJSON(r, &body)
	canon, pub, err := h.authn.VerifyPresented(r)
	if err != nil {
		httpjson.Error(w, http.StatusUnauthorized, "a valid signed challenge is required (see /_auth/challenge)")
		return
	}
	if body.Token != "" {
		res, err := h.svc.Attach(r.Context(), canon, pub, body.Token)
		if err != nil {
			h.fail(w, err)
			return
		}
		httpjson.Write(w, http.StatusOK, map[string]any{"principal": res.Principal, "created": res.Created})
		return
	}
	res, err := h.svc.Register(r.Context(), canon, pub)
	if err != nil {
		h.fail(w, err)
		return
	}
	out := map[string]any{"principal": res.Principal, "created": res.Created}
	if res.Created {
		out["recovery_key"] = res.RecoveryKey     // shown once
		out["recovery_codes"] = res.RecoveryCodes // shown once
	}
	httpjson.Write(w, http.StatusOK, out)
}

// --- recover (pre-auth, redeem a recovery secret → session) -----------------

func (h *Handler) recover(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpjson.Error(w, http.StatusMethodNotAllowed, "use POST")
		return
	}
	if !h.limiter.allow(remoteIP(r)) {
		httpjson.Error(w, http.StatusTooManyRequests, "rate limited")
		return
	}
	var body struct {
		Secret string `json:"secret"`
	}
	readJSON(r, &body)
	if body.Secret == "" {
		httpjson.Error(w, http.StatusBadRequest, "body must be {\"secret\": \"…\"}")
		return
	}
	res, err := h.svc.Recover(r.Context(), body.Secret)
	if err != nil {
		h.fail(w, err) // ErrInvalidRecovery → 403, uniform for unknown/consumed
		return
	}
	httpjson.Write(w, http.StatusOK, map[string]any{
		"principal": res.Principal, "token": res.Token,
		"expires_at": res.ExpiresAt.UTC().Format(time.RFC3339), "root": res.Root,
	})
}

// --- login (pre-auth, identifier + password → data-only session) ------------

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpjson.Error(w, http.StatusMethodNotAllowed, "use POST")
		return
	}
	if !h.limiter.allow(remoteIP(r)) {
		httpjson.Error(w, http.StatusTooManyRequests, "rate limited")
		return
	}
	var body struct {
		Identifier string `json:"identifier"`
		Password   string `json:"password"`
	}
	readJSON(r, &body)
	res, err := h.svc.Login(r.Context(), body.Identifier, body.Password)
	if err != nil {
		if errors.Is(err, ErrPasswordDisabled) {
			httpjson.Error(w, http.StatusNotFound, "password login is not enabled")
			return
		}
		httpjson.Error(w, http.StatusUnauthorized, "invalid credentials") // uniform (no enumeration)
		return
	}
	httpjson.Write(w, http.StatusOK, map[string]any{
		"principal": res.Principal, "token": res.Token,
		"expires_at": res.ExpiresAt.UTC().Format(time.RFC3339),
	})
}

// --- password set/change (session, owner + step-up) -------------------------

func (h *Handler) password(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpjson.Error(w, http.StatusMethodNotAllowed, "use POST")
		return
	}
	acct, _, ok := h.owner(w, r, authz.CredentialMgmt) // setting a password is credential management
	if !ok {
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	readJSON(r, &body)
	if err := h.svc.SetPassword(r.Context(), acct, body.Password, nil); err != nil {
		switch {
		case errors.Is(err, ErrPasswordTooShort), errors.Is(err, ErrPasswordTooLong), errors.Is(err, ErrPasswordBreached):
			httpjson.Error(w, http.StatusUnprocessableEntity, err.Error())
		case errors.Is(err, ErrPasswordDisabled):
			httpjson.Error(w, http.StatusNotFound, "password login is not enabled")
		default:
			h.fail(w, err)
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- credential management (session, owner) ---------------------------------

func (h *Handler) listCredentials(w http.ResponseWriter, r *http.Request) {
	acct, _, ok := h.owner(w, r, authz.CredentialMgmt)
	if !ok {
		return
	}
	creds, err := h.svc.Credentials(acct)
	if err != nil {
		httpjson.Error(w, http.StatusInternalServerError, "internal error")
		return
	}
	out := make([]map[string]any, 0, len(creds))
	for _, c := range creds {
		out = append(out, map[string]any{
			"id": c.ID, "type": c.Type, "role": c.Role, "label": c.Label,
			"added_at": c.AddedAt, "last_used": c.LastUsed, // secrets/material never returned
		})
	}
	httpjson.Write(w, http.StatusOK, map[string]any{"credentials": out})
}

func (h *Handler) attachCode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpjson.Error(w, http.StatusMethodNotAllowed, "use POST")
		return
	}
	acct, _, ok := h.owner(w, r, authz.CredentialMgmt)
	if !ok {
		return
	}
	code, err := h.svc.MintAttachCode(acct)
	if err != nil {
		h.fail(w, err)
		return
	}
	httpjson.Write(w, http.StatusOK, map[string]any{"code": code})
}

func (h *Handler) detach(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpjson.Error(w, http.StatusMethodNotAllowed, "use POST")
		return
	}
	acct, sid, ok := h.owner(w, r, authz.Destructive) // removing a credential is destructive
	if !ok {
		return
	}
	var body struct {
		ID string `json:"id"`
	}
	readJSON(r, &body)
	if body.ID == "" {
		httpjson.Error(w, http.StatusBadRequest, "body must be {\"id\": \"…\"}")
		return
	}
	if err := h.svc.Detach(r.Context(), acct, body.ID, sid); err != nil {
		h.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- session/device list (session, owner) -----------------------------------

func (h *Handler) listSessions(w http.ResponseWriter, r *http.Request) {
	acct, sid, ok := h.owner(w, r, authz.CredentialMgmt)
	if !ok {
		return
	}
	sess, err := h.svc.Sessions(acct)
	if err != nil {
		httpjson.Error(w, http.StatusInternalServerError, "internal error")
		return
	}
	out := make([]map[string]any, 0, len(sess))
	for _, s := range sess {
		out = append(out, map[string]any{
			"sid": s.SID, "cred_id": s.CredID,
			// created_at is stored as UnixNano (token-deadline precision); the API speaks
			// unix SECONDS, matching credentials' added_at/last_used.
			"created_at": s.CreatedAt / int64(time.Second),
			"current":    s.SID == sid, // the caller's own session — don't offer to revoke it
		})
	}
	httpjson.Write(w, http.StatusOK, map[string]any{"sessions": out})
}

func (h *Handler) revokeSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpjson.Error(w, http.StatusMethodNotAllowed, "use POST")
		return
	}
	acct, actingSID, ok := h.owner(w, r, authz.CredentialMgmt)
	if !ok {
		return
	}
	var body struct {
		SID string `json:"sid"`
		All bool   `json:"all"`
	}
	readJSON(r, &body)
	if !body.All && body.SID == "" {
		httpjson.Error(w, http.StatusBadRequest, "body must be {\"all\": true} or {\"sid\": \"…\"}")
		return
	}
	if err := h.svc.RevokeSessions(r.Context(), acct, actingSID, body.SID, body.All); err != nil {
		if errors.Is(err, ErrNoSuchSession) {
			httpjson.Error(w, http.StatusNotFound, "no such session")
			return
		}
		httpjson.Error(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- helpers ---------------------------------------------------------------

// owner resolves the caller's session and gates it on the action's assurance. On
// failure it writes the response and returns ok=false.
func (h *Handler) owner(w http.ResponseWriter, r *http.Request, action authz.ActionClass) (account, sidHex string, ok bool) {
	p, sid, has := h.authn.SessionPrincipal(r)
	if !has || p.IsAnonymous() {
		httpjson.Error(w, http.StatusUnauthorized, "a session token is required")
		return "", "", false
	}
	if err := authz.RequireAssurance(p.Assurance, action, h.assurance, time.Now()); err != nil {
		switch {
		case errors.Is(err, authz.ErrStepUpRequired):
			httpjson.Error(w, http.StatusUnauthorized, "step-up required: re-authenticate with a passkey, device key, or recovery key")
		case errors.Is(err, authz.ErrScopeReduced):
			httpjson.Error(w, http.StatusForbidden, "this recovery session cannot perform destructive actions yet")
		default:
			httpjson.Error(w, http.StatusForbidden, "owner capability required")
		}
		return "", "", false
	}
	return p.Name, sid, true
}

func (h *Handler) fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrInvalidCode), errors.Is(err, ErrInvalidRecovery):
		httpjson.Error(w, http.StatusForbidden, "invalid or expired code")
	case errors.Is(err, ErrKeyOnAnotherAccount), errors.Is(err, ErrLastCredential):
		httpjson.Error(w, http.StatusConflict, err.Error())
	case errors.Is(err, ErrNoSuchCredential):
		httpjson.Error(w, http.StatusNotFound, "no such credential")
	case errors.Is(err, ErrTooManyCredentials), errors.Is(err, ErrTooManyCodes):
		httpjson.Error(w, http.StatusTooManyRequests, err.Error())
	default:
		h.log.Error("quicsql/account: request failed", "err", err)
		httpjson.Error(w, http.StatusInternalServerError, "internal error")
	}
}

func readJSON(r *http.Request, v any) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
	if err != nil {
		return
	}
	_ = json.Unmarshal(body, v) // best-effort; empty/invalid ⇒ zero value
}
