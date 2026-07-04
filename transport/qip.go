package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"quicsql.net/config"
)

// qip.sh support: zero-setup, browser-trusted HTTPS for a private-network or
// loopback quicSQL server, with no private CA. qip.sh publishes a wildcard
// certificate for a zone whose names resolve only to private/loopback IPs (the
// default zone i.qip.sh maps *.i.qip.sh → 127.0.0.1). The combined cert+key PEM is
// served at https://qip.sh/cert/<zone>.pem and fetched into memory only.
//
// SECURITY CAVEAT: qip.sh publishes the matching private key PUBLICLY — that is how
// it hands out a trusted cert for a name anyone can point at their own loopback. So
// a qip certificate gives you encryption and a valid browser padlock, but NOT server
// authentication: anyone can serve the same cert, so a man-in-the-middle on the same
// private network can impersonate the server. It is meant for localhost and trusted
// LANs. For anything reachable by an untrusted party, use mode `files` (your own
// cert) — the server warns (warnQIPExposed) when a qip listener binds a non-loopback
// address.

const (
	// qipDefaultZone is the qip.sh wildcard zone used when a profile sets no
	// subdomain. *.i.qip.sh resolves to 127.0.0.1.
	qipDefaultZone = "i.qip.sh"
	// qipDefaultRefresh is how often the renewer re-checks the certificate when the
	// profile sets no refresh interval.
	qipDefaultRefresh = 12 * time.Hour
)

// qipHTTPClient bounds the qip.sh fetch so a network that is up but can't reach
// qip.sh (captive portal, firewall, service down) fails promptly instead of hanging
// on the OS connect timeout.
var qipHTTPClient = &http.Client{Timeout: 15 * time.Second}

// qipCert holds the current qip.sh certificate, swapped atomically by the renewer so
// GetCertificate always returns a fresh one without touching disk.
type qipCert struct {
	url string
	cur atomic.Pointer[tls.Certificate]
}

func newQIPCert(zone string) *qipCert {
	if zone == "" {
		zone = qipDefaultZone
	}
	return &qipCert{url: "https://qip.sh/cert/" + zone + ".pem"}
}

// fetch downloads the current combined cert-chain + key PEM and stores it.
func (q *qipCert) fetch() error {
	resp, err := qipHTTPClient.Get(q.url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: HTTP %d", q.url, resp.StatusCode)
	}
	pemBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	cert, err := tls.X509KeyPair(pemBytes, pemBytes) // combined cert-chain + key in one PEM
	if err != nil {
		return err
	}
	if cert.Leaf == nil && len(cert.Certificate) > 0 {
		cert.Leaf, _ = x509.ParseCertificate(cert.Certificate[0])
	}
	q.cur.Store(&cert)
	return nil
}

// get is the tls.Config.GetCertificate callback.
func (q *qipCert) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	if c := q.cur.Load(); c != nil {
		return c, nil
	}
	return nil, fmt.Errorf("tls: no qip.sh certificate available")
}

// renew re-fetches the certificate before it expires (qip.sh rotates roughly every
// 60 days). It checks on the interval and refreshes once the current cert is within
// 30 days of expiry; a failed refresh keeps the old cert and retries. It stops when
// ctx is canceled (server shutdown).
func (q *qipCert) renew(ctx context.Context, interval time.Duration, log *slog.Logger) {
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if c := q.cur.Load(); c != nil && c.Leaf != nil && time.Until(c.Leaf.NotAfter) > 30*24*time.Hour {
				continue
			}
			if err := q.fetch(); err != nil {
				log.Warn("quicsql: qip.sh certificate renewal failed (keeping current)", "err", err)
			}
		}
	}
}

// qipCertFor returns the qip.sh certificate for a profile's zone, fetching it once
// and starting a single renewer bound to the Set ctx. Repeated calls for the same
// zone — e.g. an h2 and an h3 listener sharing a qip profile — reuse the one fetched
// cert and renewer instead of double-fetching. A failed initial fetch is a startup
// error (fail-fast) with a hint toward the offline alternatives. Called only during
// the sequential Serve loop, so the zone cache needs no lock.
func (s *Set) qipCertFor(p config.TLSProfile) (*qipCert, error) {
	zone := p.Subdomain
	if zone == "" {
		zone = qipDefaultZone
	}
	if q, ok := s.qip[zone]; ok {
		return q, nil // already fetched + renewing for this zone
	}
	q := newQIPCert(zone)
	if err := q.fetch(); err != nil {
		return nil, fmt.Errorf("tls qip: fetch %s: %w (offline? use tls mode self_signed, or your own cert with mode files)", q.url, err)
	}
	interval := p.Refresh
	if interval <= 0 {
		interval = qipDefaultRefresh
	}
	// Fall back to the default logger rather than skipping renewal on a nil log —
	// a cert that is fetched once and never renewed would fail every handshake once
	// qip.sh rotates it (~60 days).
	log := s.log
	if log == nil {
		log = slog.Default()
	}
	go q.renew(s.ctx, interval, log)
	if s.qip == nil {
		s.qip = make(map[string]*qipCert)
	}
	s.qip[zone] = q
	return q, nil
}

// warnQIPExposed logs the shared-public-key caveat when a qip listener binds a
// non-loopback address — where the missing server authentication actually matters.
func warnQIPExposed(log *slog.Logger, name string, p config.TLSProfile, addr string) {
	if p.Mode != "qip" || isLoopbackAddr(addr) {
		return
	}
	zone := p.Subdomain
	if zone == "" {
		zone = qipDefaultZone
	}
	log.Warn("quicsql: serving a qip.sh certificate on a non-loopback address — its private key is published publicly, so this padlock is NOT server authentication (a MITM on this network can impersonate); use tls mode files for anything untrusted parties can reach",
		"listener", name, "zone", zone, "address", addr)
}

// isLoopbackAddr reports whether a listen address binds only loopback. An empty or
// 0.0.0.0/:: host (all interfaces) is NOT loopback.
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
