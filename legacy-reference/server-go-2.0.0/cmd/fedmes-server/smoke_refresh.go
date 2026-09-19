package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"image/png"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"fedmes/server/internal/provisioning"

	"github.com/makiuchi-d/gozxing"
	zxingqr "github.com/makiuchi-d/gozxing/qrcode"
)

const smokeMaximumResponseBytes int64 = 32 << 10

type smokeRedeemResponse struct {
	Version int `json:"version"`
	Device  struct {
		ID provisioning.DeviceID `json:"id"`
	} `json:"device"`
	Session struct {
		ID    provisioning.SessionID `json:"id"`
		Token string                 `json:"token"`
	} `json:"session"`
}

type smokeChallengeResponse struct {
	Version   int                              `json:"version"`
	Challenge smokeAuthenticationHTTPChallenge `json:"challenge"`
}

type smokeAuthenticationHTTPChallenge struct {
	ID        provisioning.ChallengeID      `json:"id"`
	DeviceID  provisioning.DeviceID         `json:"device_id"`
	Audience  string                        `json:"audience"`
	Purpose   provisioning.ChallengePurpose `json:"purpose"`
	Nonce     string                        `json:"nonce"`
	ExpiresAt string                        `json:"expires_at"`
}

type smokeErrorResponse struct {
	Error struct {
		Code string `json:"code"`
	} `json:"error"`
}

func runSmokeRefresh(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) error {
	flags := flag.NewFlagSet("smoke-refresh", flag.ContinueOnError)
	flags.SetOutput(stderr)
	username := flags.String("user", "grisha", "fixed family username")
	serverURLValue := flags.String("server-url", "http://127.0.0.1:8008", "reachable FedMes server origin")
	outputPath := flags.String("out", "", "temporary QR PNG path")
	ttl := flags.Duration("ttl", 5*time.Minute, "one-time invitation lifetime")
	dataDirectory := flags.String("data-dir", "data", "same server data directory used by the running EXE")
	allowHTTP := flags.Bool("allow-http", false, "allow HTTP for loopback or private LAN development")
	timeout := flags.Duration("timeout", 15*time.Second, "overall HTTP timeout")
	keepQR := flags.Bool("keep-qr", false, "keep the generated QR PNG after the test")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("smoke-refresh does not accept positional arguments")
	}
	parsedUsername, err := provisioning.ParseUsername(*username)
	if err != nil {
		return errors.New("--user must be one of grisha, papa, mama, yura, vasya")
	}
	serverURL, err := validateProvisioningServerURL(*serverURLValue, *allowHTTP)
	if err != nil {
		return err
	}
	if *timeout <= 0 || *timeout > time.Minute {
		return errors.New("--timeout must be greater than zero and at most one minute")
	}

	absoluteDataDirectory, err := filepath.Abs(strings.TrimSpace(*dataDirectory))
	if err != nil {
		return fmt.Errorf("resolve --data-dir: %w", err)
	}
	qrPath := strings.TrimSpace(*outputPath)
	if qrPath == "" {
		qrPath = filepath.Join(os.TempDir(), fmt.Sprintf("fedmes-smoke-%d.png", time.Now().UnixNano()))
	}
	qrPath, err = filepath.Abs(qrPath)
	if err != nil {
		return fmt.Errorf("resolve --out: %w", err)
	}
	if strings.ToLower(filepath.Ext(qrPath)) != ".png" {
		return errors.New("--out must name a PNG file")
	}
	if _, err := os.Lstat(qrPath); err == nil {
		return errors.New("--out already exists; choose a new path")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect --out: %w", err)
	}
	if !*keepQR {
		defer os.Remove(qrPath)
	}

	inviteArgs := []string{
		"--user", string(parsedUsername),
		"--server-url", serverURL,
		"--out", qrPath,
		"--ttl", ttl.String(),
		"--data-dir", absoluteDataDirectory,
	}
	if *allowHTTP {
		inviteArgs = append(inviteArgs, "--allow-http")
	}
	if err := runInvite(ctx, inviteArgs, io.Discard, stderr); err != nil {
		return fmt.Errorf("create QR invitation: %w", err)
	}

	payload, err := decodeProvisioningQR(qrPath)
	if err != nil {
		return fmt.Errorf("decode generated QR: %w", err)
	}
	if payload.Version != 1 || payload.Type != "fedmes.provisioning" || payload.ServerURL != serverURL || payload.Username != string(parsedUsername) || payload.Token == "" {
		return errors.New("decoded QR payload does not match the generated invitation")
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate P-256 device key: %w", err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return fmt.Errorf("encode P-256 public key: %w", err)
	}
	publicKeyBase64 := base64.StdEncoding.EncodeToString(publicDER)
	encryptionPrivateKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return fmt.Errorf("generate RSA message-encryption key: %w", err)
	}
	encryptionPublicDER, err := x509.MarshalPKIXPublicKey(&encryptionPrivateKey.PublicKey)
	if err != nil {
		return fmt.Errorf("encode RSA message-encryption public key: %w", err)
	}
	encryptionPublicKeyBase64 := base64.StdEncoding.EncodeToString(encryptionPublicDER)
	client := &http.Client{Timeout: *timeout}

	redeemRequest := map[string]any{
		"version":  2,
		"username": payload.Username,
		"token":    payload.Token,
		"device": map[string]any{
			"algorithm":       provisioning.DeviceKeyECDSAP256,
			"public_key_spki": publicKeyBase64,
		},
		"encryption": map[string]any{
			"algorithm":       "rsa-oaep-sha256",
			"public_key_spki": encryptionPublicKeyBase64,
		},
	}
	var redeemed smokeRedeemResponse
	if err := smokePostJSON(ctx, client, serverURL+"/api/v1/provisioning/redeem", redeemRequest, http.StatusCreated, &redeemed); err != nil {
		return fmt.Errorf("redeem invitation: %w", err)
	}
	if redeemed.Version != 2 || redeemed.Device.ID == "" || redeemed.Session.ID == "" || redeemed.Session.Token == "" {
		return errors.New("redeem response is missing device or session fields")
	}

	var challengeResponse smokeChallengeResponse
	if err := smokePostJSON(ctx, client, serverURL+"/api/v1/auth/challenge", map[string]any{
		"version":  1,
		"username": payload.Username,
		"purpose":  provisioning.ChallengePurposeSessionRefresh,
		"device": map[string]any{
			"algorithm":       provisioning.DeviceKeyECDSAP256,
			"public_key_spki": publicKeyBase64,
		},
	}, http.StatusCreated, &challengeResponse); err != nil {
		return fmt.Errorf("request refresh challenge: %w", err)
	}
	challenge := challengeResponse.Challenge
	if challenge.ID == "" || challenge.DeviceID != redeemed.Device.ID || challenge.Nonce == "" || challenge.Audience == "" {
		return errors.New("challenge response contains inconsistent fields")
	}

	authPayload, err := provisioning.DeviceAuthenticationPayload(
		challenge.Audience,
		parsedUsername,
		challenge.DeviceID,
		challenge.ID,
		challenge.Purpose,
		challenge.Nonce,
	)
	if err != nil {
		return fmt.Errorf("build challenge signing payload: %w", err)
	}
	digest := sha256.Sum256(authPayload)
	clear(authPayload)
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, digest[:])
	if err != nil {
		return fmt.Errorf("sign challenge: %w", err)
	}
	defer clear(signature)

	sessionRequest := map[string]any{
		"version":      1,
		"username":     payload.Username,
		"device_id":    challenge.DeviceID,
		"challenge_id": challenge.ID,
		"nonce":        challenge.Nonce,
		"purpose":      challenge.Purpose,
		"signature":    base64.StdEncoding.EncodeToString(signature),
	}
	var refreshed smokeRedeemResponse
	if err := smokePostJSON(ctx, client, serverURL+"/api/v1/auth/session", sessionRequest, http.StatusCreated, &refreshed); err != nil {
		return fmt.Errorf("refresh session: %w", err)
	}
	if refreshed.Device.ID != redeemed.Device.ID || refreshed.Session.ID == "" || refreshed.Session.Token == "" {
		return errors.New("refresh response is missing or inconsistent")
	}

	var replayError smokeErrorResponse
	if err := smokePostJSON(ctx, client, serverURL+"/api/v1/auth/session", sessionRequest, http.StatusConflict, &replayError); err != nil {
		return fmt.Errorf("verify challenge replay rejection: %w", err)
	}
	if replayError.Error.Code != string(provisioning.CodeChallengeUsed) {
		return fmt.Errorf("replay error code = %q, want %q", replayError.Error.Code, provisioning.CodeChallengeUsed)
	}
	var invitationReplayError smokeErrorResponse
	if err := smokePostJSON(ctx, client, serverURL+"/api/v1/provisioning/redeem", redeemRequest, http.StatusConflict, &invitationReplayError); err != nil {
		return fmt.Errorf("verify invitation replay rejection: %w", err)
	}
	if invitationReplayError.Error.Code != string(provisioning.CodeInvitationUsed) {
		return fmt.Errorf("invitation replay error code = %q, want %q", invitationReplayError.Error.Code, provisioning.CodeInvitationUsed)
	}

	_, err = fmt.Fprintf(
		stdout,
		"smoke refresh passed user=%s device_id=%s challenge_replay=%s invitation_replay=%s qr=%s\n",
		parsedUsername,
		redeemed.Device.ID,
		replayError.Error.Code,
		invitationReplayError.Error.Code,
		qrPath,
	)
	return err
}

func decodeProvisioningQR(path string) (provisioningQRPayload, error) {
	file, err := os.Open(path)
	if err != nil {
		return provisioningQRPayload{}, err
	}
	defer file.Close()
	imageValue, err := png.Decode(file)
	if err != nil {
		return provisioningQRPayload{}, err
	}
	bitmap, err := gozxing.NewBinaryBitmapFromImage(imageValue)
	if err != nil {
		return provisioningQRPayload{}, err
	}
	result, err := zxingqr.NewQRCodeReader().Decode(bitmap, nil)
	if err != nil {
		return provisioningQRPayload{}, err
	}
	var payload provisioningQRPayload
	decoder := json.NewDecoder(strings.NewReader(result.GetText()))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return provisioningQRPayload{}, err
	}
	if err := smokeRequireJSONEOF(decoder); err != nil {
		return provisioningQRPayload{}, err
	}
	return payload, nil
}

func smokeRequireJSONEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("multiple JSON values")
	}
	return err
}

func smokePostJSON(ctx context.Context, client *http.Client, endpoint string, requestValue any, expectedStatus int, responseValue any) error {
	body, err := json.Marshal(requestValue)
	if err != nil {
		return err
	}
	defer clear(body)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	limited := io.LimitReader(response.Body, smokeMaximumResponseBytes+1)
	responseBody, err := io.ReadAll(limited)
	if err != nil {
		return err
	}
	defer clear(responseBody)
	if int64(len(responseBody)) > smokeMaximumResponseBytes {
		return errors.New("response body is too large")
	}
	if response.StatusCode != expectedStatus {
		var protocolFailure smokeErrorResponse
		_ = json.Unmarshal(responseBody, &protocolFailure)
		return fmt.Errorf("HTTP %d, expected %d, error_code=%q", response.StatusCode, expectedStatus, protocolFailure.Error.Code)
	}
	if err := json.Unmarshal(responseBody, responseValue); err != nil {
		return fmt.Errorf("decode HTTP %d response: %w", response.StatusCode, err)
	}
	return nil
}
