package httpserver

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"fedmes/server/internal/messaging"
)

const (
	blindMaxJSON       = int64(12 << 20)
	blindDefaultTTL    = 72 * time.Hour
	blindMaximumTTL    = 7 * 24 * time.Hour
	blindRouteMaxLife  = 30 * 24 * time.Hour
	blindDefaultMaxObj = 2 << 20
	blindDefaultQueue  = 512
)

type blindObjectHTTP struct {
	store *messaging.Store
	now   func() time.Time
}

type blindRouteRequest struct {
	Version       int    `json:"version"`
	RouteDigest   string `json:"route_digest"`
	Generation    int64  `json:"generation"`
	LifetimeSecs  int64  `json:"lifetime_seconds"`
	MaxObjectSize int    `json:"max_object_bytes"`
	MaxPending    int    `json:"max_pending_objects"`
}

type blindObjectWrite struct {
	Version      int    `json:"version"`
	ObjectID     string `json:"object_id"`
	LengthClass  int    `json:"length_class"`
	Ciphertext   string `json:"ciphertext"`
	LifetimeSecs int64  `json:"lifetime_seconds"`
}

type blindObjectRead struct {
	ObjectID    string `json:"object_id"`
	LengthClass int    `json:"length_class"`
	Ciphertext  string `json:"ciphertext"`
}

func registerBlindObjectRoutes(mux *http.ServeMux, store *messaging.Store) {
	if store == nil {
		return
	}
	h := &blindObjectHTTP{store: store, now: time.Now}
	// Route creation requires an authenticated READY device but intentionally
	// persists no account/device relation. The route digest becomes a capability.
	auth := (&messagingHTTP{store: store, now: time.Now}).auth
	registerLimiter := newIPRateLimiter(60, time.Minute, 4096, time.Now)
	objectLimiter := newIPRateLimiter(2400, time.Minute, 16384, time.Now)
	mux.Handle("PUT /api/v4/object/route", registerLimiter.middleware(auth(http.HandlerFunc(h.registerRoute))))
	mux.Handle("POST /api/v4/object", objectLimiter.middleware(http.HandlerFunc(h.putObject)))
	mux.Handle("GET /api/v4/object", objectLimiter.middleware(http.HandlerFunc(h.pullObjects)))
	mux.Handle("DELETE /api/v4/object/{objectID}", objectLimiter.middleware(http.HandlerFunc(h.ackObject)))
}

func (h *blindObjectHTTP) registerRoute(w http.ResponseWriter, r *http.Request) {
	var req blindRouteRequest
	if !decodeBlindJSON(w, r, &req) {
		return
	}
	if req.Version != 1 || req.Generation <= 0 {
		writeAPIError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	digest, err := rawURL(req.RouteDigest, 32, 32)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	defer clear(digest)
	life := time.Duration(req.LifetimeSecs) * time.Second
	if life <= 0 {
		life = 24 * time.Hour
	}
	if life > blindRouteMaxLife {
		writeAPIError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	maxObj := req.MaxObjectSize
	if maxObj == 0 {
		maxObj = blindDefaultMaxObj
	}
	if maxObj < 1024 || maxObj > 8<<20 {
		writeAPIError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	maxPending := req.MaxPending
	if maxPending == 0 {
		maxPending = blindDefaultQueue
	}
	if maxPending < 1 || maxPending > 4096 {
		writeAPIError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	now := h.now().UTC()
	expires := now.Add(life)
	_, err = h.store.DB.ExecContext(r.Context(), `
		INSERT INTO blind_routes(route_digest,generation,created_at,expires_at,max_object_bytes,max_pending_objects,revoked_at)
		VALUES(?,?,?,?,?,?,NULL)
		ON CONFLICT(route_digest) DO UPDATE SET
			generation=excluded.generation,
			expires_at=CASE WHEN excluded.expires_at>blind_routes.expires_at THEN excluded.expires_at ELSE blind_routes.expires_at END,
			max_object_bytes=excluded.max_object_bytes,
			max_pending_objects=excluded.max_pending_objects,
			revoked_at=NULL`, digest, req.Generation, now.Format(time.RFC3339Nano), expires.Format(time.RFC3339Nano), maxObj, maxPending)
	if err != nil {
		if requestCanceled(r, err) {
			return
		}
		writeAPIError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *blindObjectHTTP) putObject(w http.ResponseWriter, r *http.Request) {
	digest, route, ok := h.routeCapability(w, r)
	if !ok {
		return
	}
	defer clear(route)
	defer clear(digest)
	var req blindObjectWrite
	if !decodeBlindJSON(w, r, &req) {
		return
	}
	if req.Version != 1 || req.LengthClass < 1 || req.LengthClass > 16 || !validOpaqueID(req.ObjectID) {
		writeAPIError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	ciphertext, err := rawURL(req.Ciphertext, 16, 8<<20)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	defer clear(ciphertext)
	var maxBytes, maxPending int
	var routeExpiry string
	err = h.store.DB.QueryRowContext(r.Context(), `SELECT max_object_bytes,max_pending_objects,expires_at FROM blind_routes WHERE route_digest=? AND revoked_at IS NULL`, digest).Scan(&maxBytes, &maxPending, &routeExpiry)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeAPIError(w, http.StatusNotFound, "route_unavailable")
			return
		}
		writeAPIError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	now := h.now().UTC()
	exp, err := time.Parse(time.RFC3339Nano, routeExpiry)
	if err != nil || !now.Before(exp) {
		writeAPIError(w, http.StatusGone, "route_expired")
		return
	}
	if len(ciphertext) > maxBytes {
		writeAPIError(w, http.StatusRequestEntityTooLarge, "object_too_large")
		return
	}
	var pending int
	if err = h.store.DB.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM blind_objects WHERE route_digest=? AND expires_at>?`, digest, now.Format(time.RFC3339Nano)).Scan(&pending); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	if pending >= maxPending {
		writeAPIError(w, http.StatusTooManyRequests, "route_full")
		return
	}
	life := time.Duration(req.LifetimeSecs) * time.Second
	if life <= 0 {
		life = blindDefaultTTL
	}
	if life > blindMaximumTTL {
		life = blindMaximumTTL
	}
	objExp := now.Add(life)
	if objExp.After(exp) {
		objExp = exp
	}
	hash := sha256.Sum256(ciphertext)
	_, err = h.store.DB.ExecContext(r.Context(), `INSERT INTO blind_objects(object_id,route_digest,length_class,ciphertext,ciphertext_sha256,created_at,expires_at) VALUES(?,?,?,?,?,?,?)`, req.ObjectID, digest, req.LengthClass, ciphertext, hash[:], now.Format(time.RFC3339Nano), objExp.Format(time.RFC3339Nano))
	if err != nil {
		writeAPIError(w, http.StatusConflict, "object_rejected")
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (h *blindObjectHTTP) pullObjects(w http.ResponseWriter, r *http.Request) {
	digest, route, ok := h.routeCapability(w, r)
	if !ok {
		return
	}
	defer clear(route)
	defer clear(digest)
	limit := 64
	if raw := r.URL.Query().Get("limit"); raw != "" {
		v, e := strconv.Atoi(raw)
		if e != nil || v < 1 || v > 256 {
			writeAPIError(w, http.StatusBadRequest, "invalid_request")
			return
		}
		limit = v
	}
	now := h.now().UTC()
	if _, err := h.store.DB.ExecContext(r.Context(), `DELETE FROM blind_objects WHERE expires_at<=?`, now.Format(time.RFC3339Nano)); err != nil && requestCanceled(r, err) {
		return
	}
	rows, err := h.store.DB.QueryContext(r.Context(), `SELECT object_id,length_class,ciphertext FROM blind_objects WHERE route_digest=? AND expires_at>? ORDER BY created_at,object_id LIMIT ?`, digest, now.Format(time.RFC3339Nano), limit)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	defer rows.Close()
	out := make([]blindObjectRead, 0, limit)
	for rows.Next() {
		var id string
		var cls int
		var ct []byte
		if err := rows.Scan(&id, &cls, &ct); err != nil {
			writeAPIError(w, http.StatusInternalServerError, "internal_error")
			return
		}
		out = append(out, blindObjectRead{ObjectID: id, LengthClass: cls, Ciphertext: base64.RawURLEncoding.EncodeToString(ct)})
		clear(ct)
	}
	if err := rows.Err(); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": 1, "objects": out})
}

func (h *blindObjectHTTP) ackObject(w http.ResponseWriter, r *http.Request) {
	digest, route, ok := h.routeCapability(w, r)
	if !ok {
		return
	}
	defer clear(route)
	defer clear(digest)
	id := strings.TrimSpace(r.PathValue("objectID"))
	if !validOpaqueID(id) {
		writeAPIError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	result, err := h.store.DB.ExecContext(r.Context(), `DELETE FROM blind_objects WHERE object_id=? AND route_digest=?`, id, digest)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		writeAPIError(w, http.StatusNotFound, "object_unavailable")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *blindObjectHTTP) routeCapability(w http.ResponseWriter, r *http.Request) ([]byte, []byte, bool) {
	raw := strings.TrimSpace(r.Header.Get("X-Object-Capability"))
	route, err := rawURL(raw, 32, 32)
	if err != nil {
		writeAPIError(w, http.StatusUnauthorized, "capability_invalid")
		return nil, nil, false
	}
	sum := sha256.Sum256(route)
	digest := append([]byte(nil), sum[:]...)
	return digest, route, true
}
func decodeBlindJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	body := http.MaxBytesReader(w, r.Body, blindMaxJSON)
	defer body.Close()
	dec := json.NewDecoder(body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_request")
		return false
	}
	if dec.Decode(&struct{}{}) != io.EOF {
		writeAPIError(w, http.StatusBadRequest, "invalid_request")
		return false
	}
	return true
}
func rawURL(value string, min, max int) ([]byte, error) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(b) < min || len(b) > max {
		clear(b)
		return nil, errors.New("invalid")
	}
	return b, nil
}
func validOpaqueID(v string) bool {
	if len(v) < 20 || len(v) > 64 {
		return false
	}
	for _, r := range v {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_') {
			return false
		}
	}
	return true
}
func randomOpaqueID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	defer clear(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
func cleanupBlindObjects(ctx context.Context, db *sql.DB, now time.Time) {
	_, _ = db.ExecContext(ctx, `DELETE FROM blind_objects WHERE expires_at<=?`, now.UTC().Format(time.RFC3339Nano))
	_, _ = db.ExecContext(ctx, `DELETE FROM blind_routes WHERE expires_at<=?`, now.UTC().Format(time.RFC3339Nano))
}
