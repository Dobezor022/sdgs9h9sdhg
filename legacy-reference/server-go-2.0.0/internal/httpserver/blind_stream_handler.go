package httpserver

import (
	"bufio"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"

	"fedmes/server/internal/messaging"
)

const (
	maxRealtimeFrame = 256 << 10
	streamQueueDepth = 96
)

type blindStreamHTTP struct {
	store  *messaging.Store
	now    func() time.Time
	broker *streamBroker
}

type streamBroker struct {
	mu     sync.Mutex
	routes map[[32]byte]map[uint64]chan []byte
	next   uint64
}

func newStreamBroker() *streamBroker {
	return &streamBroker{routes: make(map[[32]byte]map[uint64]chan []byte)}
}

func (b *streamBroker) subscribe(route [32]byte) (uint64, <-chan []byte, func()) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.next++
	id := b.next
	if b.routes[route] == nil {
		b.routes[route] = make(map[uint64]chan []byte)
	}
	ch := make(chan []byte, streamQueueDepth)
	b.routes[route][id] = ch
	return id, ch, func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		if m := b.routes[route]; m != nil {
			if c, ok := m[id]; ok {
				delete(m, id)
				close(c)
			}
			if len(m) == 0 {
				delete(b.routes, route)
			}
		}
	}
}

func (b *streamBroker) publish(route [32]byte, frame []byte) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	subscribers := b.routes[route]
	delivered := 0
	for _, ch := range subscribers {
		copyFrame := append([]byte(nil), frame...)
		select {
		case ch <- copyFrame:
			delivered++
		default:
			// Realtime invariant: never let an old frame create unbounded latency.
			select {
			case old := <-ch:
				clear(old)
			default:
			}
			select {
			case ch <- copyFrame:
				delivered++
			default:
				clear(copyFrame)
			}
		}
	}
	return delivered
}

func registerBlindStreamRoutes(mux *http.ServeMux, store *messaging.Store) {
	if store == nil {
		return
	}
	h := &blindStreamHTTP{store: store, now: time.Now, broker: newStreamBroker()}
	limiter := newIPRateLimiter(12000, time.Minute, 32768, time.Now)
	mux.Handle("GET /api/v4/stream", limiter.middleware(http.HandlerFunc(h.downstream)))
	mux.Handle("POST /api/v4/stream", limiter.middleware(http.HandlerFunc(h.upstream)))
}

func (h *blindStreamHTTP) downstream(w http.ResponseWriter, r *http.Request) {
	route, ok := h.validRoute(w, r)
	if !ok {
		return
	}
	id, frames, cancel := h.broker.subscribe(route)
	_ = id
	defer cancel()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher, ok := w.(http.Flusher)
	if !ok {
		return
	}
	flusher.Flush()
	var length [4]byte
	for {
		select {
		case <-r.Context().Done():
			return
		case frame, open := <-frames:
			if !open {
				return
			}
			if len(frame) == 0 || len(frame) > maxRealtimeFrame {
				clear(frame)
				continue
			}
			binary.BigEndian.PutUint32(length[:], uint32(len(frame)))
			if _, err := w.Write(length[:]); err != nil {
				clear(frame)
				return
			}
			if _, err := w.Write(frame); err != nil {
				clear(frame)
				return
			}
			clear(frame)
			flusher.Flush()
		}
	}
}

func (h *blindStreamHTTP) upstream(w http.ResponseWriter, r *http.Request) {
	route, ok := h.validRoute(w, r)
	if !ok {
		return
	}
	reader := bufio.NewReaderSize(http.MaxBytesReader(w, r.Body, 64<<20), 64<<10)
	defer r.Body.Close()
	var length [4]byte
	for {
		if _, err := io.ReadFull(reader, length[:]); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break
			}
			return
		}
		n := int(binary.BigEndian.Uint32(length[:]))
		if n < 1 || n > maxRealtimeFrame {
			writeAPIError(w, http.StatusBadRequest, "invalid_frame")
			return
		}
		frame := make([]byte, n)
		if _, err := io.ReadFull(reader, frame); err != nil {
			clear(frame)
			return
		}
		h.broker.publish(route, frame)
		clear(frame)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *blindStreamHTTP) validRoute(w http.ResponseWriter, r *http.Request) ([32]byte, bool) {
	var out [32]byte
	raw := r.Header.Get("X-Object-Capability")
	capability, err := rawURL(raw, 32, 32)
	if err != nil {
		writeAPIError(w, http.StatusUnauthorized, "capability_invalid")
		return out, false
	}
	defer clear(capability)
	out = sha256.Sum256(capability)
	var expiry string
	var revoked sql.NullString
	err = h.store.DB.QueryRowContext(r.Context(), `SELECT expires_at,revoked_at FROM blind_routes WHERE route_digest=?`, out[:]).Scan(&expiry, &revoked)
	if err != nil {
		writeAPIError(w, http.StatusNotFound, "route_unavailable")
		return out, false
	}
	t, err := time.Parse(time.RFC3339Nano, expiry)
	if err != nil || revoked.Valid || !h.now().UTC().Before(t) {
		writeAPIError(w, http.StatusGone, "route_expired")
		return out, false
	}
	return out, true
}
