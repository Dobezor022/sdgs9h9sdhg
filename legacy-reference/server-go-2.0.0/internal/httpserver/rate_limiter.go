package httpserver

import (
	"net"
	"net/http"
	"sync"
	"time"
)

type rateLimitEntry struct {
	count    int
	resetAt  time.Time
	lastSeen time.Time
}

type ipRateLimiter struct {
	mu         sync.Mutex
	entries    map[string]rateLimitEntry
	limit      int
	window     time.Duration
	maxEntries int
	now        func() time.Time
}

func newIPRateLimiter(limit int, window time.Duration, maxEntries int, now func() time.Time) *ipRateLimiter {
	return &ipRateLimiter{
		entries:    make(map[string]rateLimitEntry),
		limit:      limit,
		window:     window,
		maxEntries: maxEntries,
		now:        now,
	}
}

func (limiter *ipRateLimiter) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !limiter.allow(clientIP(r.RemoteAddr)) {
			w.Header().Set("Retry-After", "60")
			writeProtocolError(w, http.StatusTooManyRequests, "rate_limited")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (limiter *ipRateLimiter) allow(ip string) bool {
	now := limiter.now().UTC()
	limiter.mu.Lock()
	defer limiter.mu.Unlock()

	entry, exists := limiter.entries[ip]
	if exists && !now.Before(entry.resetAt) {
		delete(limiter.entries, ip)
		exists = false
	}
	if !exists {
		limiter.removeExpired(now)
		if len(limiter.entries) >= limiter.maxEntries {
			limiter.removeOldest()
		}
		limiter.entries[ip] = rateLimitEntry{count: 1, resetAt: now.Add(limiter.window), lastSeen: now}
		return true
	}
	entry.lastSeen = now
	entry.count++
	limiter.entries[ip] = entry
	return entry.count <= limiter.limit
}

func (limiter *ipRateLimiter) removeExpired(now time.Time) {
	for ip, entry := range limiter.entries {
		if !now.Before(entry.resetAt) {
			delete(limiter.entries, ip)
		}
	}
}

func (limiter *ipRateLimiter) removeOldest() {
	var oldestIP string
	var oldestTime time.Time
	for ip, entry := range limiter.entries {
		if oldestIP == "" || entry.lastSeen.Before(oldestTime) {
			oldestIP = ip
			oldestTime = entry.lastSeen
		}
	}
	if oldestIP != "" {
		delete(limiter.entries, oldestIP)
	}
}

func clientIP(remoteAddress string) string {
	host, _, err := net.SplitHostPort(remoteAddress)
	if err != nil || host == "" {
		return remoteAddress
	}
	return host
}
