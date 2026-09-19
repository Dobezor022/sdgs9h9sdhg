package httpserver

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"fedmes/server/internal/accountsecurity"
	"fedmes/server/internal/messaging"
)

const (
	securityProtocolVersion     = 3
	maximumSecurityRequestBytes = int64(18 << 20)
)

type accountSecurityHTTP struct {
	store          *accountsecurity.Store
	messagingStore *messaging.Store
	logger         *slog.Logger
	now            func() time.Time
}

type vaultWriteHTTPRequest struct {
	Version                  int    `json:"version"`
	ExpectedPreviousRevision int64  `json:"expected_previous_revision"`
	VaultVersion             int    `json:"vault_version"`
	CryptoVersion            int    `json:"crypto_version"`
	AADVersion               int    `json:"aad_version"`
	Nonce                    string `json:"nonce"`
	Ciphertext               string `json:"ciphertext"`
	CiphertextSHA256         string `json:"ciphertext_sha256"`
	AccessVerifier           string `json:"access_verifier"`
}

type recoveryWriteHTTPRequest struct {
	Version          int    `json:"version"`
	ID               string `json:"id"`
	VaultRevision    int64  `json:"vault_revision"`
	PackageVersion   int    `json:"package_version"`
	CryptoVersion    int    `json:"crypto_version"`
	AADVersion       int    `json:"aad_version"`
	KDFName          string `json:"kdf_name"`
	KDFParameters    string `json:"kdf_parameters"`
	Salt             string `json:"salt"`
	Nonce            string `json:"nonce"`
	Ciphertext       string `json:"ciphertext"`
	CiphertextSHA256 string `json:"ciphertext_sha256"`
}

type completeRecoveryRequest struct {
	Version        int    `json:"version"`
	VaultRevision  int64  `json:"vault_revision"`
	AccessVerifier string `json:"access_verifier"`
}

type approveSecurityDeviceRequest struct {
	Version              int    `json:"version"`
	CertificateID        string `json:"certificate_id"`
	CertificateVersion   int    `json:"certificate_version"`
	CertificatePayload   string `json:"certificate_payload"`
	CertificateSignature string `json:"certificate_signature"`
	SignatureAlgorithm   string `json:"signature_algorithm"`
	EncryptedPackage     string `json:"encrypted_package"`
	Nonce                string `json:"nonce"`
	AADVersion           int    `json:"aad_version"`
	PackageVersion       int    `json:"package_version"`
	RequestSignature     string `json:"request_signature"`
}

type completeProvisioningRequest struct {
	Version        int    `json:"version"`
	VaultRevision  int64  `json:"vault_revision"`
	AccessVerifier string `json:"access_verifier"`
}

type securityVersionRequest struct {
	Version int `json:"version"`
}

func registerAccountSecurityRoutes(mux *http.ServeMux, messagingStore *messaging.Store, logger *slog.Logger) {
	if messagingStore == nil || messagingStore.DB == nil {
		return
	}
	h := &accountSecurityHTTP{
		store:          accountsecurity.NewStore(messagingStore.DB),
		messagingStore: messagingStore,
		logger:         logger,
		now:            time.Now,
	}
	limiter := newIPRateLimiter(120, time.Minute, 8192, time.Now)
	protected := func(handler http.HandlerFunc) http.Handler {
		return limiter.middleware(h.auth(handler))
	}
	mux.Handle("GET /api/v2/security/state", protected(h.getState))
	mux.Handle("GET /api/v2/security/vault", protected(h.getVault))
	mux.Handle("PUT /api/v2/security/vault", protected(h.putVault))
	mux.Handle("GET /api/v2/security/recovery-package", protected(h.getRecoveryPackage))
	mux.Handle("PUT /api/v2/security/recovery-package", protected(h.putRecoveryPackage))
	mux.Handle("POST /api/v2/security/recovery/complete", protected(h.completeRecovery))
	mux.Handle("GET /api/v2/security/device-requests", protected(h.listDeviceRequests))
	mux.Handle("GET /api/v2/security/device-requests/{requestID}", protected(h.getCurrentDeviceRequest))
	mux.Handle("POST /api/v2/security/device-requests/{requestID}/approve", protected(h.approveDeviceRequest))
	mux.Handle("POST /api/v2/security/device-requests/{requestID}/reject", protected(h.rejectDeviceRequest))
	mux.Handle("GET /api/v2/security/device-requests/{requestID}/package", protected(h.getProvisioningPackage))
	mux.Handle("POST /api/v2/security/device-requests/{requestID}/complete", protected(h.completeProvisioning))
	mux.Handle("DELETE /api/v2/security/devices/{deviceID}", protected(h.revokeDevice))
	mux.Handle("GET /api/v2/security/migrations", protected(h.listMigrations))
}

func (h *accountSecurityHTTP) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := strings.TrimSpace(r.Header.Get("Authorization"))
		if !strings.HasPrefix(header, "Bearer ") || len(header) <= 7 {
			writeAPIError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		principal, err := h.messagingStore.Authenticate(r.Context(), strings.TrimSpace(header[7:]), h.now().UTC())
		if err != nil || principal.SecurityState == accountsecurity.StateRevoked {
			writeAPIError(w, http.StatusUnauthorized, "session_invalid")
			return
		}
		ctx := context.WithValue(r.Context(), principalContextKey{}, principal)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func securityPrincipal(r *http.Request) accountsecurity.Principal {
	principal := requestPrincipal(r)
	return accountsecurity.Principal{
		Username: principal.Username, DeviceID: principal.DeviceID, SessionID: principal.SessionID,
	}
}

func (h *accountSecurityHTTP) getState(w http.ResponseWriter, r *http.Request) {
	state, err := h.store.GetAccountState(r.Context(), securityPrincipal(r))
	if err != nil {
		h.writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": securityProtocolVersion, "security": state})
}

func (h *accountSecurityHTTP) getVault(w http.ResponseWriter, r *http.Request) {
	vault, err := h.store.GetLatestVault(r.Context(), securityPrincipal(r))
	if err != nil {
		h.writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, vaultHTTPResponse(vault))
}

func vaultHTTPResponse(vault accountsecurity.VaultEnvelope) map[string]any {
	return map[string]any{
		"version":           securityProtocolVersion,
		"revision":          vault.Revision,
		"vault_version":     vault.VaultVersion,
		"crypto_version":    vault.CryptoVersion,
		"aad_version":       vault.AADVersion,
		"nonce":             base64.StdEncoding.EncodeToString(vault.Nonce),
		"ciphertext":        base64.StdEncoding.EncodeToString(vault.Ciphertext),
		"ciphertext_sha256": hex.EncodeToString(vault.CiphertextHash[:]),
		"created_at":        vault.CreatedAt.Format(time.RFC3339Nano),
		"updated_at":        vault.UpdatedAt.Format(time.RFC3339Nano),
	}
}

func (h *accountSecurityHTTP) putVault(w http.ResponseWriter, r *http.Request) {
	requestID, ok := securityRequestID(w, r)
	if !ok {
		return
	}
	var request vaultWriteHTTPRequest
	raw, ok := decodeSecurityJSON(w, r, &request)
	if !ok {
		return
	}
	defer clear(raw)
	if request.Version != securityProtocolVersion {
		writeAPIError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	nonce, ok := decodeStandardBase64(request.Nonce, 12, 24)
	if !ok {
		writeAPIError(w, http.StatusBadRequest, "invalid_nonce")
		return
	}
	defer clear(nonce)
	ciphertext, ok := decodeStandardBase64(request.Ciphertext, 16, 16<<20)
	if !ok {
		writeAPIError(w, http.StatusBadRequest, "invalid_ciphertext")
		return
	}
	defer clear(ciphertext)
	hash, ok := decodeHexHash(request.CiphertextSHA256)
	if !ok {
		writeAPIError(w, http.StatusBadRequest, "invalid_ciphertext_hash")
		return
	}
	accessVerifierBytes, ok := decodeStandardBase64(request.AccessVerifier, sha256.Size, sha256.Size)
	if !ok {
		writeAPIError(w, http.StatusBadRequest, "invalid_access_verifier")
		return
	}
	defer clear(accessVerifierBytes)
	var accessVerifier [sha256.Size]byte
	copy(accessVerifier[:], accessVerifierBytes)
	requestDigest := sha256.Sum256(raw)
	vault, replayed, err := h.store.PutVault(r.Context(), securityPrincipal(r), accountsecurity.VaultWrite{
		ExpectedPreviousRevision: request.ExpectedPreviousRevision,
		VaultVersion:             request.VaultVersion, CryptoVersion: request.CryptoVersion, AADVersion: request.AADVersion,
		Nonce: nonce, Ciphertext: ciphertext, CiphertextHash: hash, AccessVerifier: accessVerifier,
		RequestID: requestID, RequestDigest: requestDigest,
	}, h.now().UTC())
	if err != nil {
		h.writeError(w, err)
		return
	}
	status := http.StatusCreated
	if replayed {
		status = http.StatusOK
	}
	writeJSON(w, status, vaultHTTPResponse(vault))
}

func (h *accountSecurityHTTP) getRecoveryPackage(w http.ResponseWriter, r *http.Request) {
	pkg, err := h.store.GetActiveRecoveryPackage(r.Context(), securityPrincipal(r))
	if err != nil {
		h.writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, recoveryHTTPResponse(pkg))
}

func recoveryHTTPResponse(pkg accountsecurity.RecoveryPackage) map[string]any {
	return map[string]any{
		"version":           securityProtocolVersion,
		"id":                pkg.ID,
		"vault_revision":    pkg.VaultRevision,
		"package_version":   pkg.PackageVersion,
		"crypto_version":    pkg.CryptoVersion,
		"aad_version":       pkg.AADVersion,
		"kdf_name":          pkg.KDFName,
		"kdf_parameters":    pkg.KDFParameters,
		"salt":              base64.StdEncoding.EncodeToString(pkg.Salt),
		"nonce":             base64.StdEncoding.EncodeToString(pkg.Nonce),
		"ciphertext":        base64.StdEncoding.EncodeToString(pkg.Ciphertext),
		"ciphertext_sha256": hex.EncodeToString(pkg.CiphertextHash[:]),
		"created_at":        pkg.CreatedAt.Format(time.RFC3339Nano),
	}
}

func (h *accountSecurityHTTP) putRecoveryPackage(w http.ResponseWriter, r *http.Request) {
	requestID, ok := securityRequestID(w, r)
	if !ok {
		return
	}
	var request recoveryWriteHTTPRequest
	raw, ok := decodeSecurityJSON(w, r, &request)
	if !ok {
		return
	}
	defer clear(raw)
	if request.Version != securityProtocolVersion || !validOpaqueIdentifier(request.ID, 16, 128) {
		writeAPIError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	salt, ok := decodeStandardBase64(request.Salt, 16, 64)
	if !ok {
		writeAPIError(w, http.StatusBadRequest, "invalid_salt")
		return
	}
	defer clear(salt)
	nonce, ok := decodeStandardBase64(request.Nonce, 12, 24)
	if !ok {
		writeAPIError(w, http.StatusBadRequest, "invalid_nonce")
		return
	}
	defer clear(nonce)
	ciphertext, ok := decodeStandardBase64(request.Ciphertext, 16, 1<<20)
	if !ok {
		writeAPIError(w, http.StatusBadRequest, "invalid_ciphertext")
		return
	}
	defer clear(ciphertext)
	hash, ok := decodeHexHash(request.CiphertextSHA256)
	if !ok {
		writeAPIError(w, http.StatusBadRequest, "invalid_ciphertext_hash")
		return
	}
	requestDigest := sha256.Sum256(raw)
	pkg, replayed, err := h.store.PutRecoveryPackage(r.Context(), securityPrincipal(r), accountsecurity.RecoveryWrite{
		ID: request.ID, VaultRevision: request.VaultRevision, PackageVersion: request.PackageVersion,
		CryptoVersion: request.CryptoVersion, AADVersion: request.AADVersion,
		KDFName: request.KDFName, KDFParameters: request.KDFParameters,
		Salt: salt, Nonce: nonce, Ciphertext: ciphertext, CiphertextHash: hash,
		RequestID: requestID, RequestDigest: requestDigest,
	}, h.now().UTC())
	if err != nil {
		h.writeError(w, err)
		return
	}
	status := http.StatusCreated
	if replayed {
		status = http.StatusOK
	}
	writeJSON(w, status, recoveryHTTPResponse(pkg))
}

func (h *accountSecurityHTTP) completeRecovery(w http.ResponseWriter, r *http.Request) {
	var request completeRecoveryRequest
	if _, ok := decodeSecurityJSON(w, r, &request); !ok {
		return
	}
	if request.Version != securityProtocolVersion || request.VaultRevision <= 0 {
		writeAPIError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	accessVerifierBytes, ok := decodeStandardBase64(request.AccessVerifier, sha256.Size, sha256.Size)
	if !ok {
		writeAPIError(w, http.StatusBadRequest, "invalid_access_verifier")
		return
	}
	defer clear(accessVerifierBytes)
	var accessVerifier [sha256.Size]byte
	copy(accessVerifier[:], accessVerifierBytes)
	if err := h.store.CompleteRecovery(r.Context(), securityPrincipal(r), request.VaultRevision, accessVerifier, h.now().UTC()); err != nil {
		h.writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *accountSecurityHTTP) listDeviceRequests(w http.ResponseWriter, r *http.Request) {
	requests, err := h.store.ListPendingDeviceRequests(r.Context(), securityPrincipal(r), h.now().UTC())
	if err != nil {
		h.writeError(w, err)
		return
	}
	items := make([]map[string]any, 0, len(requests))
	for _, request := range requests {
		items = append(items, deviceRequestHTTPResponse(request))
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": securityProtocolVersion, "requests": items})
}

func (h *accountSecurityHTTP) getCurrentDeviceRequest(w http.ResponseWriter, r *http.Request) {
	requestID := strings.TrimSpace(r.PathValue("requestID"))
	if !validOpaqueIdentifier(requestID, 16, 128) {
		writeAPIError(w, http.StatusBadRequest, "invalid_request_id")
		return
	}
	request, err := h.store.GetDeviceRequestForTarget(r.Context(), securityPrincipal(r), requestID, h.now().UTC())
	if err != nil {
		h.writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": securityProtocolVersion, "request": deviceRequestHTTPResponse(request)})
}

func deviceRequestHTTPResponse(request accountsecurity.DeviceProvisioningRequest) map[string]any {
	result := map[string]any{
		"id":                        request.ID,
		"username":                  request.Username,
		"target_device_id":          request.TargetDeviceID,
		"display_name":              request.DisplayName,
		"platform":                  request.Platform,
		"network_hint":              request.NetworkHint,
		"protocol_version":          request.ProtocolVersion,
		"requested_at":              request.RequestedAt.Format(time.RFC3339Nano),
		"expires_at":                request.ExpiresAt.Format(time.RFC3339Nano),
		"signing_algorithm":         request.SigningAlgorithm,
		"signing_public_key_spki":   base64.StdEncoding.EncodeToString(request.SigningPublicKey),
		"signing_fingerprint":       hex.EncodeToString(request.SigningFingerprint[:]),
		"key_agreement_algorithm":   request.KeyAlgorithm,
		"key_agreement_public_key":  base64.StdEncoding.EncodeToString(request.KeyPublicKey),
		"key_agreement_fingerprint": hex.EncodeToString(request.KeyFingerprint[:]),
	}
	if request.ApprovedAt != nil {
		result["approved_at"] = request.ApprovedAt.Format(time.RFC3339Nano)
		result["approved_by_device_id"] = request.ApprovedByDeviceID
	}
	if request.RejectedAt != nil {
		result["rejected_at"] = request.RejectedAt.Format(time.RFC3339Nano)
	}
	if request.CompletedAt != nil {
		result["completed_at"] = request.CompletedAt.Format(time.RFC3339Nano)
	}
	return result
}

func (h *accountSecurityHTTP) approveDeviceRequest(w http.ResponseWriter, r *http.Request) {
	requestID := strings.TrimSpace(r.PathValue("requestID"))
	idempotencyID, ok := securityRequestID(w, r)
	if !ok {
		return
	}
	if !validOpaqueIdentifier(requestID, 16, 128) {
		writeAPIError(w, http.StatusBadRequest, "invalid_request_id")
		return
	}
	var request approveSecurityDeviceRequest
	raw, ok := decodeSecurityJSON(w, r, &request)
	if !ok {
		return
	}
	defer clear(raw)
	if request.Version != securityProtocolVersion || !validOpaqueIdentifier(request.CertificateID, 16, 128) {
		writeAPIError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	certificate, ok := decodeStandardBase64(request.CertificatePayload, 32, 16<<10)
	if !ok {
		writeAPIError(w, http.StatusBadRequest, "invalid_certificate")
		return
	}
	defer clear(certificate)
	certificateSignature, ok := decodeStandardBase64(request.CertificateSignature, 32, 2048)
	if !ok {
		writeAPIError(w, http.StatusBadRequest, "invalid_certificate_signature")
		return
	}
	defer clear(certificateSignature)
	encryptedPackage, ok := decodeStandardBase64(request.EncryptedPackage, 48, 1<<20)
	if !ok {
		writeAPIError(w, http.StatusBadRequest, "invalid_provisioning_package")
		return
	}
	defer clear(encryptedPackage)
	nonce, ok := decodeStandardBase64(request.Nonce, 12, 24)
	if !ok {
		writeAPIError(w, http.StatusBadRequest, "invalid_nonce")
		return
	}
	defer clear(nonce)
	requestSignature, ok := decodeStandardBase64(request.RequestSignature, 32, 2048)
	if !ok {
		writeAPIError(w, http.StatusUnauthorized, "invalid_device_signature")
		return
	}
	defer clear(requestSignature)

	principal := requestPrincipal(r)
	// The approver loads the pending request through the ready-device listing.
	pending, err := h.store.ListPendingDeviceRequests(r.Context(), securityPrincipal(r), h.now().UTC())
	if err != nil {
		h.writeError(w, err)
		return
	}
	var target *accountsecurity.DeviceProvisioningRequest
	for index := range pending {
		if pending[index].ID == requestID {
			target = &pending[index]
			break
		}
	}
	if target == nil {
		writeAPIError(w, http.StatusNotFound, "security_request_not_found")
		return
	}
	algorithm, approverPublicKey, err := h.messagingStore.LoadActiveDeviceIdentity(r.Context(), principal)
	if err != nil {
		writeAPIError(w, http.StatusUnauthorized, "session_invalid")
		return
	}
	defer clear(approverPublicKey)
	if request.SignatureAlgorithm != algorithm ||
		!messaging.VerifyDeviceLinkApprovalSignature(algorithm, approverPublicKey, certificate, certificateSignature) {
		writeAPIError(w, http.StatusUnauthorized, "invalid_certificate_signature")
		return
	}
	packageHash := sha256.Sum256(encryptedPackage)
	certificateHash := sha256.Sum256(certificate)
	canonical := []byte(strings.Join([]string{
		"fedmes-device-approval-v1",
		requestID,
		principal.DeviceID,
		target.TargetDeviceID,
		hex.EncodeToString(target.SigningFingerprint[:]),
		hex.EncodeToString(target.KeyFingerprint[:]),
		fmt.Sprintf("%d", request.PackageVersion),
		hex.EncodeToString(packageHash[:]),
		hex.EncodeToString(certificateHash[:]),
	}, "\n"))
	defer clear(canonical)
	if !messaging.VerifyDeviceLinkApprovalSignature(algorithm, approverPublicKey, canonical, requestSignature) {
		writeAPIError(w, http.StatusUnauthorized, "invalid_device_signature")
		return
	}
	requestDigest := sha256.Sum256(raw)
	replayed, err := h.store.ApproveDeviceRequest(r.Context(), accountsecurity.ProvisioningApproval{
		RequestID:     requestID,
		Approver:      accountsecurity.Principal{Username: principal.Username, DeviceID: principal.DeviceID, SessionID: principal.SessionID},
		CertificateID: request.CertificateID, CertificateVersion: request.CertificateVersion,
		CertificatePayload: certificate, SignatureAlgorithm: request.SignatureAlgorithm,
		Signature: certificateSignature, EncryptedPackage: encryptedPackage, Nonce: nonce,
		AADVersion: request.AADVersion, PackageVersion: request.PackageVersion,
		CanonicalRequest: canonical, RequestSignature: requestSignature,
		IdempotencyRequestID: idempotencyID, IdempotencyDigest: requestDigest,
	}, h.now().UTC())
	if err != nil {
		h.writeError(w, err)
		return
	}
	status := http.StatusCreated
	if replayed {
		status = http.StatusOK
	}
	writeJSON(w, status, map[string]any{"version": securityProtocolVersion, "status": "approved"})
}

func (h *accountSecurityHTTP) rejectDeviceRequest(w http.ResponseWriter, r *http.Request) {
	requestID := strings.TrimSpace(r.PathValue("requestID"))
	var request securityVersionRequest
	if _, ok := decodeSecurityJSON(w, r, &request); !ok {
		return
	}
	if request.Version != securityProtocolVersion || !validOpaqueIdentifier(requestID, 16, 128) {
		writeAPIError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if err := h.store.RejectDeviceRequest(r.Context(), securityPrincipal(r), requestID, h.now().UTC()); err != nil {
		h.writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *accountSecurityHTTP) getProvisioningPackage(w http.ResponseWriter, r *http.Request) {
	requestID := strings.TrimSpace(r.PathValue("requestID"))
	if !validOpaqueIdentifier(requestID, 16, 128) {
		writeAPIError(w, http.StatusBadRequest, "invalid_request_id")
		return
	}
	pkg, err := h.store.GetProvisioningPackage(r.Context(), securityPrincipal(r), requestID, h.now().UTC())
	if err != nil {
		h.writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version":               securityProtocolVersion,
		"request_id":            pkg.RequestID,
		"target_device_id":      pkg.TargetDeviceID,
		"encrypted_package":     base64.StdEncoding.EncodeToString(pkg.Encrypted),
		"nonce":                 base64.StdEncoding.EncodeToString(pkg.Nonce),
		"aad_version":           pkg.AADVersion,
		"package_version":       pkg.PackageVersion,
		"created_at":            pkg.CreatedAt.Format(time.RFC3339Nano),
		"certificate_id":        pkg.CertificateID,
		"certificate_payload":   base64.StdEncoding.EncodeToString(pkg.Certificate),
		"certificate_signature": base64.StdEncoding.EncodeToString(pkg.CertificateSig),
		"signature_algorithm":   pkg.SignatureAlgo,
		"issuer_device_id":      pkg.IssuerDeviceID,
	})
}

func (h *accountSecurityHTTP) completeProvisioning(w http.ResponseWriter, r *http.Request) {
	requestID := strings.TrimSpace(r.PathValue("requestID"))
	var request completeProvisioningRequest
	if _, ok := decodeSecurityJSON(w, r, &request); !ok {
		return
	}
	if request.Version != securityProtocolVersion || request.VaultRevision <= 0 || !validOpaqueIdentifier(requestID, 16, 128) {
		writeAPIError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	accessVerifierBytes, ok := decodeStandardBase64(request.AccessVerifier, sha256.Size, sha256.Size)
	if !ok {
		writeAPIError(w, http.StatusBadRequest, "invalid_access_verifier")
		return
	}
	defer clear(accessVerifierBytes)
	var accessVerifier [sha256.Size]byte
	copy(accessVerifier[:], accessVerifierBytes)
	if err := h.store.CompleteProvisioning(r.Context(), securityPrincipal(r), requestID, request.VaultRevision, accessVerifier, h.now().UTC()); err != nil {
		h.writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *accountSecurityHTTP) revokeDevice(w http.ResponseWriter, r *http.Request) {
	deviceID := strings.TrimSpace(r.PathValue("deviceID"))
	if !validOpaqueIdentifier(deviceID, 16, 128) {
		writeAPIError(w, http.StatusBadRequest, "invalid_device_id")
		return
	}
	if err := h.store.RevokeDevice(r.Context(), securityPrincipal(r), deviceID, h.now().UTC()); err != nil {
		h.writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *accountSecurityHTTP) listMigrations(w http.ResponseWriter, r *http.Request) {
	items, err := h.store.ListMigrations(r.Context(), securityPrincipal(r))
	if err != nil {
		h.writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": securityProtocolVersion, "migrations": items})
}

func (h *accountSecurityHTTP) writeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, accountsecurity.ErrNotFound):
		writeAPIError(w, http.StatusNotFound, "security_record_not_found")
	case errors.Is(err, accountsecurity.ErrForbidden):
		writeAPIError(w, http.StatusForbidden, "security_operation_forbidden")
	case errors.Is(err, accountsecurity.ErrRequestExpired):
		writeAPIError(w, http.StatusGone, "security_request_expired")
	case errors.Is(err, accountsecurity.ErrInvalidState):
		writeAPIError(w, http.StatusLocked, "keys_not_ready")
	case errors.Is(err, accountsecurity.ErrConflict),
		errors.Is(err, accountsecurity.ErrRequestReplayed),
		errors.Is(err, accountsecurity.ErrAlreadyCompleted):
		writeAPIError(w, http.StatusConflict, "security_state_conflict")
	default:
		if h.logger != nil {
			h.logger.Error("account security operation failed", "error_code", "internal_error", "cause", err.Error())
		}
		writeAPIError(w, http.StatusInternalServerError, "internal_error")
	}
}

func securityRequestID(w http.ResponseWriter, r *http.Request) (string, bool) {
	value := strings.TrimSpace(r.Header.Get("X-FedMes-Request-ID"))
	if !validOpaqueIdentifier(value, 16, 128) {
		writeAPIError(w, http.StatusBadRequest, "invalid_request_id")
		return "", false
	}
	return value, true
}

func decodeSecurityJSON(w http.ResponseWriter, r *http.Request, target any) ([]byte, bool) {
	if !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
		writeAPIError(w, http.StatusUnsupportedMediaType, "unsupported_media_type")
		return nil, false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maximumSecurityRequestBytes)
	defer r.Body.Close()
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_json")
		return nil, false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil || requireJSONEOF(decoder) != nil {
		clear(raw)
		writeAPIError(w, http.StatusBadRequest, "invalid_json")
		return nil, false
	}
	return raw, true
}

func decodeStandardBase64(value string, minimum, maximum int) ([]byte, bool) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(value))
	if err != nil || len(decoded) < minimum || len(decoded) > maximum {
		clear(decoded)
		return nil, false
	}
	return decoded, true
}

func decodeHexHash(value string) ([32]byte, bool) {
	var result [32]byte
	decoded, err := hex.DecodeString(strings.TrimSpace(value))
	if err != nil || len(decoded) != sha256.Size {
		clear(decoded)
		return result, false
	}
	copy(result[:], decoded)
	clear(decoded)
	return result, true
}

func validOpaqueIdentifier(value string, minimum, maximum int) bool {
	if len(value) < minimum || len(value) > maximum {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			character == '-' || character == '_' || character == '.' {
			continue
		}
		return false
	}
	return true
}

func constantTimeEqual(left, right []byte) bool {
	return len(left) == len(right) && hmac.Equal(left, right)
}
