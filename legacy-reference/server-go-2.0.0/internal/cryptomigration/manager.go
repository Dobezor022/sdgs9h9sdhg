package cryptomigration

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
)

type Manager struct {
	db                   *sql.DB
	mediaDir, stagingDir string
	now                  func() time.Time
}

func NewManager(db *sql.DB, mediaDir string) (*Manager, error) {
	if db == nil || mediaDir == "" {
		return nil, ErrInvalid
	}
	staging := filepath.Join(mediaDir, ".migration-staging")
	if err := os.MkdirAll(staging, 0o700); err != nil {
		return nil, err
	}
	return &Manager{db: db, mediaDir: mediaDir, stagingDir: staging, now: time.Now}, nil
}

func (m *Manager) Start(ctx context.Context, p Principal, kind string) (Migration, bool, error) {
	if kind != "legacy_fmk" && kind != "message_crypto_v2" && kind != "media_crypto_v2" {
		return Migration{}, false, ErrInvalid
	}
	if err := m.requireReady(ctx, p); err != nil {
		return Migration{}, false, err
	}
	var existing Migration
	var created, updated string
	var completed sql.NullString
	err := m.db.QueryRowContext(ctx, `SELECT id,username,migration_kind,source_version,target_version,state,last_sequence,processed_count,verified_count,created_at,updated_at,completed_at FROM crypto_migrations WHERE username=? AND migration_kind=? AND source_version=1 AND target_version=2`, p.Username, kind).Scan(&existing.ID, &existing.Username, &existing.Kind, &existing.SourceVersion, &existing.TargetVersion, &existing.State, &existing.LastSequence, &existing.ProcessedCount, &existing.VerifiedCount, &created, &updated, &completed)
	if err == nil {
		hydrateMigration(&existing, created, updated, completed)
		return existing, true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Migration{}, false, err
	}
	now := m.now().UTC()
	id := uuid.NewString()
	_, err = m.db.ExecContext(ctx, `INSERT INTO crypto_migrations(id,username,migration_kind,source_version,target_version,state,last_sequence,processed_count,verified_count,created_at,updated_at) VALUES(?,?,?,?,?,'running',0,0,0,?,?)`, id, p.Username, kind, 1, 2, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	if err != nil {
		return Migration{}, false, err
	}
	return Migration{ID: id, Username: p.Username, Kind: kind, SourceVersion: 1, TargetVersion: 2, State: "running", CreatedAt: now, UpdatedAt: now}, false, nil
}
func (m *Manager) Get(ctx context.Context, p Principal, id string) (Migration, error) {
	var out Migration
	var created, updated string
	var completed sql.NullString
	err := m.db.QueryRowContext(ctx, `SELECT id,username,migration_kind,source_version,target_version,state,last_sequence,processed_count,verified_count,created_at,updated_at,completed_at FROM crypto_migrations WHERE id=?`, id).Scan(&out.ID, &out.Username, &out.Kind, &out.SourceVersion, &out.TargetVersion, &out.State, &out.LastSequence, &out.ProcessedCount, &out.VerifiedCount, &created, &updated, &completed)
	if errors.Is(err, sql.ErrNoRows) {
		return Migration{}, ErrNotFound
	}
	if err != nil {
		return Migration{}, err
	}
	if out.Username != p.Username {
		return Migration{}, ErrForbidden
	}
	hydrateMigration(&out, created, updated, completed)
	return out, nil
}
func hydrateMigration(out *Migration, created, updated string, completed sql.NullString) {
	out.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	out.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
	if completed.Valid {
		v, _ := time.Parse(time.RFC3339Nano, completed.String)
		out.CompletedAt = &v
	}
}

func (m *Manager) ListMessages(ctx context.Context, p Principal, migrationID string, after int64, limit int) ([]LegacyMessage, error) {
	mig, err := m.Get(ctx, p, migrationID)
	if err != nil {
		return nil, err
	}
	if mig.Kind != "legacy_fmk" && mig.Kind != "message_crypto_v2" {
		return nil, ErrInvalid
	}
	if limit < 1 || limit > 100 || after < 0 {
		return nil, ErrInvalid
	}
	rows, err := m.db.QueryContext(ctx, `SELECT sequence,id,chat_id,sender_username,sender_device_id,ciphertext,nonce,aad,ciphertext_sha256,created_at FROM messages WHERE sender_username=? AND crypto_version=1 AND sequence>? AND deleted_at IS NULL ORDER BY sequence LIMIT ?`, p.Username, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]LegacyMessage, 0, limit)
	for rows.Next() {
		var x LegacyMessage
		var hash []byte
		var created string
		if err := rows.Scan(&x.Sequence, &x.ID, &x.ChatID, &x.SenderUsername, &x.SenderDeviceID, &x.Ciphertext, &x.Nonce, &x.AAD, &hash, &created); err != nil {
			return nil, err
		}
		computed := sha256.Sum256(x.Ciphertext)
		if len(hash) == 0 {
			_, _ = m.db.ExecContext(ctx, `UPDATE messages SET ciphertext_sha256=? WHERE id=? AND ciphertext_sha256 IS NULL`, computed[:], x.ID)
			x.CiphertextSHA256 = computed
		} else if len(hash) == 32 {
			copy(x.CiphertextSHA256[:], hash)
		} else {
			return nil, ErrConflict
		}
		x.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		out = append(out, x)
	}
	return out, rows.Err()
}

func (m *Manager) UploadMessage(ctx context.Context, p Principal, in MessageReplacement) error {
	if err := m.requireReady(ctx, p); err != nil {
		return err
	}
	if in.MigrationID == "" || in.MessageID == "" || in.TargetCryptoVersion != 2 || in.TargetAADVersion != 2 || in.TargetRoomKeyVersion < 1 || len(in.TargetCiphertext) < 16 || len(in.TargetCiphertext) > 1<<20 || len(in.TargetNonce) != 12 || len(in.TargetAAD) < 1 || len(in.TargetAAD) > 4096 || len(in.TargetAlgorithm) < 8 || len(in.TargetAlgorithm) > 96 || len(in.Signature) < 32 || len(in.Signature) > 2048 {
		return ErrInvalid
	}
	computed := sha256.Sum256(in.TargetCiphertext)
	if !hmac.Equal(computed[:], in.TargetHash[:]) {
		return ErrInvalid
	}
	mig, err := m.Get(ctx, p, in.MigrationID)
	if err != nil {
		return err
	}
	if mig.State != "running" && mig.State != "paused" {
		return ErrConflict
	}
	var sender string
	var source []byte
	var version int
	if err := m.db.QueryRowContext(ctx, `SELECT sender_username,ciphertext_sha256,crypto_version FROM messages WHERE id=? AND deleted_at IS NULL`, in.MessageID).Scan(&sender, &source, &version); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if sender != p.Username || version != 1 || len(source) != 32 || !hmac.Equal(source, in.SourceHash[:]) {
		return ErrConflict
	}
	canonical := canonicalMessageUpload(in)
	if !m.verifyDeviceSignature(ctx, p.DeviceID, canonical, in.Signature) {
		return ErrForbidden
	}
	now := m.now().UTC().Format(time.RFC3339Nano)
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO crypto_message_replacements(migration_id,message_id,source_ciphertext_sha256,target_ciphertext,target_nonce,target_aad,target_crypto_version,target_room_key_version,target_aad_version,target_encryption_algorithm,target_ciphertext_sha256,uploaded_by_device_id,upload_signature,uploaded_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(migration_id,message_id) DO UPDATE SET target_ciphertext=excluded.target_ciphertext,target_nonce=excluded.target_nonce,target_aad=excluded.target_aad,target_crypto_version=excluded.target_crypto_version,target_room_key_version=excluded.target_room_key_version,target_aad_version=excluded.target_aad_version,target_encryption_algorithm=excluded.target_encryption_algorithm,target_ciphertext_sha256=excluded.target_ciphertext_sha256,uploaded_by_device_id=excluded.uploaded_by_device_id,upload_signature=excluded.upload_signature,uploaded_at=excluded.uploaded_at,verified_by_device_id=NULL,verification_signature=NULL,verified_at=NULL`, in.MigrationID, in.MessageID, in.SourceHash[:], in.TargetCiphertext, in.TargetNonce, in.TargetAAD, in.TargetCryptoVersion, in.TargetRoomKeyVersion, in.TargetAADVersion, in.TargetAlgorithm, in.TargetHash[:], p.DeviceID, in.Signature, now)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO crypto_migration_records(migration_id,object_kind,object_id,source_crypto_version,target_crypto_version,source_ciphertext_sha256,target_ciphertext_sha256,verified_by_device_id,device_signature,state,created_at,updated_at) VALUES(?,'message',?,1,2,?,?,NULL,NULL,'uploaded',?,?) ON CONFLICT(migration_id,object_kind,object_id) DO UPDATE SET target_ciphertext_sha256=excluded.target_ciphertext_sha256,verified_by_device_id=NULL,device_signature=NULL,state='uploaded',updated_at=excluded.updated_at`, in.MigrationID, in.MessageID, in.SourceHash[:], in.TargetHash[:], now, now)
	if err != nil {
		return err
	}
	return tx.Commit()
}
func (m *Manager) GetMessageReplacement(ctx context.Context, p Principal, migrationID, messageID string) (MessageReplacementView, error) {
	if _, err := m.Get(ctx, p, migrationID); err != nil {
		return MessageReplacementView{}, err
	}
	var out MessageReplacementView
	var source, target []byte
	var uploaded string
	err := m.db.QueryRowContext(ctx, `SELECT migration_id,message_id,source_ciphertext_sha256,target_ciphertext,target_nonce,target_aad,target_crypto_version,target_room_key_version,target_aad_version,target_encryption_algorithm,target_ciphertext_sha256,uploaded_by_device_id,upload_signature,uploaded_at FROM crypto_message_replacements WHERE migration_id=? AND message_id=?`, migrationID, messageID).Scan(&out.MigrationID, &out.MessageID, &source, &out.TargetCiphertext, &out.TargetNonce, &out.TargetAAD, &out.TargetCryptoVersion, &out.TargetRoomKeyVersion, &out.TargetAADVersion, &out.TargetAlgorithm, &target, &out.UploadedByDeviceID, &out.Signature, &uploaded)
	if errors.Is(err, sql.ErrNoRows) {
		return MessageReplacementView{}, ErrNotFound
	}
	if err != nil {
		return MessageReplacementView{}, err
	}
	copy(out.SourceHash[:], source)
	copy(out.TargetHash[:], target)
	out.UploadedAt, _ = time.Parse(time.RFC3339Nano, uploaded)
	return out, nil
}
func (m *Manager) VerifyMessage(ctx context.Context, p Principal, migrationID, messageID string, signature []byte) error {
	if err := m.requireReady(ctx, p); err != nil {
		return err
	}
	view, err := m.GetMessageReplacement(ctx, p, migrationID, messageID)
	if err != nil {
		return err
	}
	canonical := canonicalMessageVerify(view)
	if !m.verifyDeviceSignature(ctx, p.DeviceID, canonical, signature) {
		return ErrForbidden
	}
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var current []byte
	var version int
	if err := tx.QueryRowContext(ctx, `SELECT ciphertext_sha256,crypto_version FROM messages WHERE id=?`, messageID).Scan(&current, &version); err != nil {
		return err
	}
	if version != 1 || len(current) != 32 || !hmac.Equal(current, view.SourceHash[:]) {
		return ErrConflict
	}
	var duplicate int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM messages WHERE sender_device_id=(SELECT sender_device_id FROM messages WHERE id=?) AND chat_id=(SELECT chat_id FROM messages WHERE id=?) AND room_key_version=? AND nonce=? AND id<>?`, messageID, messageID, view.TargetRoomKeyVersion, view.TargetNonce, messageID).Scan(&duplicate); err != nil {
		return err
	}
	if duplicate != 0 {
		return ErrConflict
	}
	now := m.now().UTC().Format(time.RFC3339Nano)
	_, err = tx.ExecContext(ctx, `UPDATE messages SET ciphertext=?,nonce=?,aad=?,crypto_version=?,room_key_version=?,aad_version=?,encryption_algorithm=?,ciphertext_sha256=?,legacy_retired_at=? WHERE id=? AND crypto_version=1`, view.TargetCiphertext, view.TargetNonce, view.TargetAAD, view.TargetCryptoVersion, view.TargetRoomKeyVersion, view.TargetAADVersion, view.TargetAlgorithm, view.TargetHash[:], now, messageID)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE crypto_message_replacements SET verified_by_device_id=?,verification_signature=?,verified_at=? WHERE migration_id=? AND message_id=?`, p.DeviceID, signature, now, migrationID, messageID)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE crypto_migration_records SET verified_by_device_id=?,device_signature=?,state='retired',updated_at=? WHERE migration_id=? AND object_kind='message' AND object_id=?`, p.DeviceID, signature, now, migrationID, messageID)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE crypto_migrations SET last_sequence=MAX(last_sequence,(SELECT sequence FROM messages WHERE id=?)),processed_count=processed_count+1,verified_count=verified_count+1,updated_at=? WHERE id=?`, messageID, now, migrationID)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (m *Manager) ListMedia(ctx context.Context, p Principal, migrationID string, limit int) ([]LegacyMedia, error) {
	mig, err := m.Get(ctx, p, migrationID)
	if err != nil {
		return nil, err
	}
	if mig.Kind != "legacy_fmk" && mig.Kind != "media_crypto_v2" {
		return nil, ErrInvalid
	}
	if limit < 1 || limit > 100 {
		return nil, ErrInvalid
	}
	rows, err := m.db.QueryContext(ctx, `SELECT id,chat_id,size_bytes,COALESCE(ciphertext_sha256,sha256_digest),created_at FROM media_objects WHERE uploader_username=? AND crypto_version=1 AND deleted_at IS NULL ORDER BY created_at LIMIT ?`, p.Username, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]LegacyMedia, 0, limit)
	for rows.Next() {
		var x LegacyMedia
		var hash []byte
		var created string
		if err := rows.Scan(&x.ID, &x.ChatID, &x.SizeBytes, &hash, &created); err != nil {
			return nil, err
		}
		if len(hash) != 32 {
			return nil, ErrConflict
		}
		copy(x.CiphertextSHA256[:], hash)
		x.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		out = append(out, x)
	}
	return out, rows.Err()
}
func (m *Manager) StageMedia(ctx context.Context, p Principal, in MediaStageInput, reader io.Reader, sizeLimit int64) (MediaReplacementView, error) {
	if err := m.requireReady(ctx, p); err != nil {
		return MediaReplacementView{}, err
	}
	if in.TargetCryptoVersion != 2 || len(in.TargetAlgorithm) < 8 || len(in.TargetAlgorithm) > 96 || len(in.Signature) < 32 || len(in.Signature) > 2048 || sizeLimit < 1 || sizeLimit > 268435456 {
		return MediaReplacementView{}, ErrInvalid
	}
	mig, err := m.Get(ctx, p, in.MigrationID)
	if err != nil {
		return MediaReplacementView{}, err
	}
	if mig.Kind != "legacy_fmk" && mig.Kind != "media_crypto_v2" {
		return MediaReplacementView{}, ErrInvalid
	}
	var uploader string
	var current []byte
	var version int
	if err := m.db.QueryRowContext(ctx, `SELECT uploader_username,COALESCE(ciphertext_sha256,sha256_digest),crypto_version FROM media_objects WHERE id=? AND deleted_at IS NULL`, in.MediaID).Scan(&uploader, &current, &version); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return MediaReplacementView{}, ErrNotFound
		}
		return MediaReplacementView{}, err
	}
	if uploader != p.Username || version != 1 || len(current) != 32 || !hmac.Equal(current, in.SourceHash[:]) {
		return MediaReplacementView{}, ErrConflict
	}
	if !m.verifyDeviceSignature(ctx, p.DeviceID, canonicalMediaUpload(in), in.Signature) {
		return MediaReplacementView{}, ErrForbidden
	}
	name := hex.EncodeToString(randomBytes(24)) + ".stage"
	path := filepath.Join(m.stagingDir, name)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return MediaReplacementView{}, err
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	hash := sha256.New()
	written, err := io.Copy(io.MultiWriter(file, hash), io.LimitReader(reader, sizeLimit+1))
	if err != nil || written < 1 || written > sizeLimit {
		return MediaReplacementView{}, ErrInvalid
	}
	if err := file.Sync(); err != nil {
		return MediaReplacementView{}, err
	}
	if err := file.Close(); err != nil {
		return MediaReplacementView{}, err
	}
	computed := hash.Sum(nil)
	if !hmac.Equal(computed, in.TargetHash[:]) {
		return MediaReplacementView{}, ErrInvalid
	}
	now := m.now().UTC()
	_, err = m.db.ExecContext(ctx, `INSERT INTO crypto_media_replacements(migration_id,media_id,source_ciphertext_sha256,staged_blob_name,target_size_bytes,target_ciphertext_sha256,target_crypto_version,target_encryption_algorithm,uploaded_by_device_id,upload_signature,uploaded_at) VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(migration_id,media_id) DO UPDATE SET source_ciphertext_sha256=excluded.source_ciphertext_sha256,staged_blob_name=excluded.staged_blob_name,target_size_bytes=excluded.target_size_bytes,target_ciphertext_sha256=excluded.target_ciphertext_sha256,target_crypto_version=excluded.target_crypto_version,target_encryption_algorithm=excluded.target_encryption_algorithm,uploaded_by_device_id=excluded.uploaded_by_device_id,upload_signature=excluded.upload_signature,uploaded_at=excluded.uploaded_at,verified_by_device_id=NULL,verification_signature=NULL,verified_at=NULL`, in.MigrationID, in.MediaID, in.SourceHash[:], name, written, in.TargetHash[:], in.TargetCryptoVersion, in.TargetAlgorithm, p.DeviceID, in.Signature, now.Format(time.RFC3339Nano))
	if err != nil {
		return MediaReplacementView{}, err
	}
	ok = true
	return MediaReplacementView{MigrationID: in.MigrationID, MediaID: in.MediaID, StagedBlobName: name, SourceHash: in.SourceHash, TargetHash: in.TargetHash, TargetSizeBytes: written, TargetCryptoVersion: in.TargetCryptoVersion, TargetAlgorithm: in.TargetAlgorithm, UploadedByDeviceID: p.DeviceID, UploadedAt: now}, nil
}
func (m *Manager) GetMediaReplacement(ctx context.Context, p Principal, migrationID, mediaID string) (MediaReplacementView, error) {
	if _, err := m.Get(ctx, p, migrationID); err != nil {
		return MediaReplacementView{}, err
	}
	var out MediaReplacementView
	var source, target []byte
	var uploaded string
	err := m.db.QueryRowContext(ctx, `SELECT migration_id,media_id,source_ciphertext_sha256,staged_blob_name,target_size_bytes,target_ciphertext_sha256,target_crypto_version,target_encryption_algorithm,uploaded_by_device_id,uploaded_at FROM crypto_media_replacements WHERE migration_id=? AND media_id=?`, migrationID, mediaID).Scan(&out.MigrationID, &out.MediaID, &source, &out.StagedBlobName, &out.TargetSizeBytes, &target, &out.TargetCryptoVersion, &out.TargetAlgorithm, &out.UploadedByDeviceID, &uploaded)
	if errors.Is(err, sql.ErrNoRows) {
		return MediaReplacementView{}, ErrNotFound
	}
	if err != nil {
		return MediaReplacementView{}, err
	}
	copy(out.SourceHash[:], source)
	copy(out.TargetHash[:], target)
	out.UploadedAt, _ = time.Parse(time.RFC3339Nano, uploaded)
	return out, nil
}
func (m *Manager) OpenStagedMedia(ctx context.Context, p Principal, migrationID, mediaID string) (*os.File, MediaReplacementView, error) {
	view, err := m.GetMediaReplacement(ctx, p, migrationID, mediaID)
	if err != nil {
		return nil, MediaReplacementView{}, err
	}
	file, err := os.Open(filepath.Join(m.stagingDir, view.StagedBlobName))
	if err != nil {
		return nil, MediaReplacementView{}, err
	}
	return file, view, nil
}
func (m *Manager) VerifyMedia(ctx context.Context, p Principal, migrationID, mediaID string, signature []byte) error {
	if err := m.requireReady(ctx, p); err != nil {
		return err
	}
	view, err := m.GetMediaReplacement(ctx, p, migrationID, mediaID)
	if err != nil {
		return err
	}
	if !m.verifyDeviceSignature(ctx, p.DeviceID, canonicalMediaVerify(view), signature) {
		return ErrForbidden
	}
	var blobName string
	var current []byte
	var version int
	if err := m.db.QueryRowContext(ctx, `SELECT blob_name,COALESCE(ciphertext_sha256,sha256_digest),crypto_version FROM media_objects WHERE id=?`, mediaID).Scan(&blobName, &current, &version); err != nil {
		return err
	}
	if version != 1 || len(current) != 32 || !hmac.Equal(current, view.SourceHash[:]) {
		return ErrConflict
	}
	staged := filepath.Join(m.stagingDir, view.StagedBlobName)
	target := filepath.Join(m.mediaDir, blobName)
	backup := target + ".legacy-" + migrationID
	_ = os.Remove(backup)
	if err := os.Rename(target, backup); err != nil {
		return err
	}
	restored := false
	defer func() {
		if !restored {
			_ = os.Rename(backup, target)
		}
	}()
	if err := os.Rename(staged, target); err != nil {
		return err
	}
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := m.now().UTC().Format(time.RFC3339Nano)
	_, err = tx.ExecContext(ctx, `UPDATE media_objects SET size_bytes=?,sha256_digest=?,ciphertext_sha256=?,crypto_version=?,encryption_algorithm=?,legacy_retired_at=? WHERE id=? AND crypto_version=1`, view.TargetSizeBytes, view.TargetHash[:], view.TargetHash[:], view.TargetCryptoVersion, view.TargetAlgorithm, now, mediaID)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE crypto_media_replacements SET verified_by_device_id=?,verification_signature=?,verified_at=? WHERE migration_id=? AND media_id=?`, p.DeviceID, signature, now, migrationID, mediaID)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO crypto_migration_records(migration_id,object_kind,object_id,source_crypto_version,target_crypto_version,source_ciphertext_sha256,target_ciphertext_sha256,verified_by_device_id,device_signature,state,created_at,updated_at) VALUES(?,'media',?,1,2,?,?,?,?, 'retired',?,?) ON CONFLICT(migration_id,object_kind,object_id) DO UPDATE SET target_ciphertext_sha256=excluded.target_ciphertext_sha256,verified_by_device_id=excluded.verified_by_device_id,device_signature=excluded.device_signature,state='retired',updated_at=excluded.updated_at`, migrationID, mediaID, view.SourceHash[:], view.TargetHash[:], p.DeviceID, signature, now, now)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE crypto_migrations SET processed_count=processed_count+1,verified_count=verified_count+1,updated_at=? WHERE id=?`, now, migrationID)
	if err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	restored = true
	_ = os.Remove(backup)
	return nil
}

func (m *Manager) Complete(ctx context.Context, p Principal, migrationID string) error {
	mig, err := m.Get(ctx, p, migrationID)
	if err != nil {
		return err
	}
	var remaining int
	switch mig.Kind {
	case "message_crypto_v2":
		err = m.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM messages WHERE sender_username=? AND crypto_version=1 AND deleted_at IS NULL`, p.Username).Scan(&remaining)
	case "media_crypto_v2":
		err = m.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM media_objects WHERE uploader_username=? AND crypto_version=1 AND deleted_at IS NULL`, p.Username).Scan(&remaining)
	case "legacy_fmk":
		err = m.db.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM messages WHERE sender_username=? AND crypto_version=1 AND deleted_at IS NULL)+(SELECT COUNT(*) FROM media_objects WHERE uploader_username=? AND crypto_version=1 AND deleted_at IS NULL)`, p.Username, p.Username).Scan(&remaining)
	default:
		return ErrInvalid
	}
	if err != nil {
		return err
	}
	if remaining != 0 {
		return ErrIncomplete
	}
	now := m.now().UTC().Format(time.RFC3339Nano)
	_, err = m.db.ExecContext(ctx, `UPDATE crypto_migrations SET state='completed',updated_at=?,completed_at=? WHERE id=?`, now, now, migrationID)
	return err
}
func (m *Manager) RetireLegacyFMK(ctx context.Context, p Principal, vaultRevision int64, signature []byte) error {
	if err := m.requireReady(ctx, p); err != nil {
		return err
	}
	if vaultRevision < 1 || len(signature) < 32 || len(signature) > 2048 {
		return ErrInvalid
	}
	canonical := []byte(fmt.Sprintf("fedmes-legacy-fmk-retired-v1\n%s\n%d", p.Username, vaultRevision))
	if !m.verifyDeviceSignature(ctx, p.DeviceID, canonical, signature) {
		return ErrForbidden
	}
	var completed int
	if err := m.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM crypto_migrations WHERE username=? AND migration_kind='legacy_fmk' AND state='completed'`, p.Username).Scan(&completed); err != nil {
		return err
	}
	if completed != 1 {
		return ErrIncomplete
	}
	var currentRevision int64
	if err := m.db.QueryRowContext(ctx, `SELECT vault_revision FROM account_security_state WHERE username=?`, p.Username).Scan(&currentRevision); err != nil {
		return err
	}
	if currentRevision != vaultRevision {
		return ErrConflict
	}
	now := m.now().UTC().Format(time.RFC3339Nano)
	_, err := m.db.ExecContext(ctx, `UPDATE account_security_state SET crypto_version=2,minimum_crypto_version=2,legacy_fmk_removed_at=?,updated_at=? WHERE username=?`, now, now, p.Username)
	return err
}

func (m *Manager) requireReady(ctx context.Context, p Principal) error {
	var owner, state string
	var revoked sql.NullString
	err := m.db.QueryRowContext(ctx, `SELECT username,security_state,revoked_at FROM provisioning_devices WHERE id=?`, p.DeviceID).Scan(&owner, &state, &revoked)
	if err != nil || owner != p.Username || revoked.Valid || state != "READY" {
		return ErrForbidden
	}
	return nil
}
func (m *Manager) verifyDeviceSignature(ctx context.Context, deviceID string, message, signature []byte) bool {
	var alg string
	var spki []byte
	if err := m.db.QueryRowContext(ctx, `SELECT key_algorithm,public_key_spki FROM provisioning_devices WHERE id=? AND revoked_at IS NULL`, deviceID).Scan(&alg, &spki); err != nil {
		return false
	}
	key, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return false
	}
	digest := sha256.Sum256(message)
	switch alg {
	case "ed25519":
		pub, ok := key.(ed25519.PublicKey)
		return ok && ed25519.Verify(pub, message, signature)
	case "ecdsa-p256-sha256":
		pub, ok := key.(*ecdsa.PublicKey)
		return ok && ecdsa.VerifyASN1(pub, digest[:], signature)
	default:
		return false
	}
}
func canonicalMessageUpload(in MessageReplacement) []byte {
	return []byte(fmt.Sprintf("fedmes-message-migration-upload-v1\n%s\n%s\n%x\n%x\n%d\n%d\n%d\n%s\n%s", in.MigrationID, in.MessageID, in.SourceHash, in.TargetHash, in.TargetCryptoVersion, in.TargetRoomKeyVersion, in.TargetAADVersion, in.TargetAlgorithm, in.TargetAAD))
}
func canonicalMessageVerify(v MessageReplacementView) []byte {
	return []byte(fmt.Sprintf("fedmes-message-migration-verify-v1\n%s\n%s\n%x\n%x", v.MigrationID, v.MessageID, v.SourceHash, v.TargetHash))
}
func canonicalMediaUpload(in MediaStageInput) []byte {
	return []byte(fmt.Sprintf("fedmes-media-migration-upload-v1\n%s\n%s\n%x\n%x\n%d\n%s", in.MigrationID, in.MediaID, in.SourceHash, in.TargetHash, in.TargetCryptoVersion, in.TargetAlgorithm))
}
func canonicalMediaVerify(v MediaReplacementView) []byte {
	return []byte(fmt.Sprintf("fedmes-media-migration-verify-v1\n%s\n%s\n%x\n%x\n%d", v.MigrationID, v.MediaID, v.SourceHash, v.TargetHash, v.TargetSizeBytes))
}
func randomBytes(n int) []byte {
	out := make([]byte, n)
	if _, err := rand.Read(out); err != nil {
		panic(err)
	}
	return out
}
func (m *Manager) CleanupStaging(maxAge time.Duration) error {
	entries, err := os.ReadDir(m.stagingDir)
	if err != nil {
		return err
	}
	cutoff := m.now().Add(-maxAge)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err == nil && info.ModTime().Before(cutoff) {
			var count int
			_ = m.db.QueryRow(`SELECT COUNT(*) FROM crypto_media_replacements WHERE staged_blob_name=? AND verified_at IS NULL`, entry.Name()).Scan(&count)
			if count == 0 {
				_ = os.Remove(filepath.Join(m.stagingDir, entry.Name()))
			}
		}
	}
	return nil
}

var _ = strings.Builder{}
