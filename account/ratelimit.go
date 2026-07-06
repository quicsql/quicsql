package account

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// A per-IP token bucket throttles the unauthenticated join/recover endpoints — the
// same shape as the enroll limiter: burst bucketBurst, refill rate_per_ip/sec, with a
// hard cap on the map (an attacker cycling source IPs can't grow it without bound).
const (
	bucketBurst = 3
	maxBuckets  = 4096
)

type bucket struct {
	tokens float64
	last   time.Time
}

type ipLimiter struct {
	rate    float64 // sustained tokens/sec/IP; <=0 disables limiting
	mu      sync.Mutex
	buckets map[string]*bucket
}

func newIPLimiter(rate float64) *ipLimiter {
	return &ipLimiter{rate: rate, buckets: map[string]*bucket{}}
}

// allow admits or rejects one request from ip.
func (l *ipLimiter) allow(ip string) bool {
	if l.rate <= 0 {
		return true
	}
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if b := l.buckets[ip]; b != nil {
		b.tokens = min(bucketBurst, b.tokens+now.Sub(b.last).Seconds()*l.rate)
		b.last = now
		if b.tokens < 1 {
			return false
		}
		b.tokens--
		return true
	}
	if len(l.buckets) >= maxBuckets {
		idle := time.Duration(float64(bucketBurst) / l.rate * float64(time.Second))
		for k, b := range l.buckets {
			if now.Sub(b.last) > idle {
				delete(l.buckets, k)
			}
		}
		if len(l.buckets) >= maxBuckets {
			return false // saturated with active IPs — shed load rather than grow
		}
	}
	l.buckets[ip] = &bucket{tokens: bucketBurst - 1, last: now}
	return true
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
