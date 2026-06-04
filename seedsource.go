package aiggwallet

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// MasterSeedSource is the pluggable input for the BIP-32 master seed that agent
// EOAs derive from (Derive / DeriveAgent / DerivePath). It is a PORT so the
// custody backend is a deployment choice, not baked into the code:
//
//   - StaticMasterSeedSource — an in-process []byte (tests / dev).
//   - EnvMasterSeedSource     — a hex seed from an env var (dev / staging).
//   - TEEMasterSeedSource     — fetched from a dstack CVM TEE sealed store over
//     HTTP+Bearer (production; strong + attestable).
//
// A KMS/HSM-backed source can be added as another implementation without
// touching consumers. Typically called once at startup; the seed then lives in
// the holding service's memory. The seed roots ALL agents, so its custody is
// the systemic trust anchor — individual agent keys are bounded by their
// Permit2 allowance, the seed is not.
type MasterSeedSource interface {
	MasterSeed(ctx context.Context) ([]byte, error)
}

// ErrMasterSeedNotConfigured signals that a source has no seed configured (so
// the caller can leave agent signing disabled rather than fail hard).
var ErrMasterSeedNotConfigured = errors.New("aiggwallet: master seed not configured")

// DefaultTEEMasterSeedPath is the AI.GG dstack TEE runtime route for the sealed
// platform master seed.
const DefaultTEEMasterSeedPath = "/sub2api/v1/platform/master-seed"

func validateSeed(seed []byte) error {
	if len(seed) < 16 || len(seed) > 64 {
		return fmt.Errorf("aiggwallet: master seed must be 16-64 bytes (got %d)", len(seed))
	}
	return nil
}

// StaticMasterSeedSource holds a fixed seed in memory (tests / dev). Production
// should prefer TEE/KMS.
type StaticMasterSeedSource struct{ Seed []byte }

func (s StaticMasterSeedSource) MasterSeed(context.Context) ([]byte, error) {
	if len(s.Seed) == 0 {
		return nil, ErrMasterSeedNotConfigured
	}
	if err := validateSeed(s.Seed); err != nil {
		return nil, err
	}
	out := make([]byte, len(s.Seed)) // defensive copy (caller may Zeroize)
	copy(out, s.Seed)
	return out, nil
}

// EnvMasterSeedSource reads a hex seed (with or without 0x) from environment
// variable Var. Empty/unset → ErrMasterSeedNotConfigured.
type EnvMasterSeedSource struct {
	Var    string                    // env var name, e.g. "WALLET_MASTER_SEED"
	Getenv func(string) string       // optional; defaults to os.Getenv
}

func (s EnvMasterSeedSource) MasterSeed(context.Context) ([]byte, error) {
	get := s.Getenv
	if get == nil {
		return nil, errors.New("aiggwallet: EnvMasterSeedSource.Getenv not set")
	}
	raw := strings.TrimSpace(get(s.Var))
	if raw == "" {
		return nil, ErrMasterSeedNotConfigured
	}
	seed, err := hex.DecodeString(strings.TrimPrefix(raw, "0x"))
	if err != nil {
		return nil, fmt.Errorf("aiggwallet: env master seed bad hex: %w", err)
	}
	if err := validateSeed(seed); err != nil {
		return nil, err
	}
	return seed, nil
}

// TEEMasterSeedSource fetches the sealed master seed from a dstack CVM TEE:
//
//	GET {BaseURL}{Path}      (Path defaults to DefaultTEEMasterSeedPath)
//	  Authorization: Bearer {ServiceToken}
//	  200 application/json: { "seed_hex": "<hex>" }
//
// The seed never leaves the TEE except to the authenticated, attested caller.
type TEEMasterSeedSource struct {
	BaseURL      string
	ServiceToken string
	Path         string       // optional; defaults to DefaultTEEMasterSeedPath
	HTTPClient   *http.Client // optional; default 15s timeout
}

func (s *TEEMasterSeedSource) MasterSeed(ctx context.Context) ([]byte, error) {
	if s == nil || strings.TrimSpace(s.BaseURL) == "" || strings.TrimSpace(s.ServiceToken) == "" {
		return nil, ErrMasterSeedNotConfigured
	}
	path := s.Path
	if path == "" {
		path = DefaultTEEMasterSeedPath
	}
	url := strings.TrimRight(s.BaseURL, "/") + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("aiggwallet: tee master seed build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+s.ServiceToken)
	client := s.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("aiggwallet: tee master seed request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<14))
	if err != nil {
		return nil, fmt.Errorf("aiggwallet: tee master seed read body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("aiggwallet: tee master seed status %d: %s", resp.StatusCode, string(body))
	}
	var payload struct {
		SeedHex string `json:"seed_hex"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("aiggwallet: tee master seed decode: %w", err)
	}
	if strings.TrimSpace(payload.SeedHex) == "" {
		return nil, errors.New("aiggwallet: tee returned empty seed_hex")
	}
	seed, err := hex.DecodeString(strings.TrimPrefix(payload.SeedHex, "0x"))
	if err != nil {
		return nil, fmt.Errorf("aiggwallet: tee master seed bad hex: %w", err)
	}
	if err := validateSeed(seed); err != nil {
		return nil, err
	}
	return seed, nil
}
