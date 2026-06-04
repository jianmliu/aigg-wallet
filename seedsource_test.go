package aiggwallet

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStaticMasterSeedSource(t *testing.T) {
	want := []byte("0123456789abcdef0123456789abcdef") // 32 bytes
	got, err := StaticMasterSeedSource{Seed: want}.MasterSeed(context.Background())
	if err != nil {
		t.Fatalf("static: %v", err)
	}
	if string(got) != string(want) {
		t.Fatal("seed mismatch")
	}
	// Mutating the returned copy must not affect the source.
	got[0] ^= 0xFF
	again, _ := StaticMasterSeedSource{Seed: want}.MasterSeed(context.Background())
	if again[0] == got[0] {
		t.Fatal("returned slice must be a defensive copy")
	}
	if _, err := (StaticMasterSeedSource{}).MasterSeed(context.Background()); !errors.Is(err, ErrMasterSeedNotConfigured) {
		t.Fatal("empty static must be ErrMasterSeedNotConfigured")
	}
	if _, err := (StaticMasterSeedSource{Seed: []byte("short")}).MasterSeed(context.Background()); err == nil {
		t.Fatal("too-short seed must error")
	}
}

func TestEnvMasterSeedSource(t *testing.T) {
	env := map[string]string{"SEED": "0x" + strings.Repeat("ab", 32)}
	src := EnvMasterSeedSource{Var: "SEED", Getenv: func(k string) string { return env[k] }}
	got, err := src.MasterSeed(context.Background())
	if err != nil {
		t.Fatalf("env: %v", err)
	}
	if hex.EncodeToString(got) != strings.Repeat("ab", 32) {
		t.Fatal("env seed mismatch")
	}
	// Unset → not configured.
	if _, err := (EnvMasterSeedSource{Var: "NOPE", Getenv: func(string) string { return "" }}).MasterSeed(context.Background()); !errors.Is(err, ErrMasterSeedNotConfigured) {
		t.Fatal("unset env must be ErrMasterSeedNotConfigured")
	}
}

func TestTEEMasterSeedSource(t *testing.T) {
	seedHex := strings.Repeat("cd", 32)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != DefaultTEEMasterSeedPath {
			w.WriteHeader(404)
			return
		}
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(401)
			return
		}
		_, _ = w.Write([]byte(`{"seed_hex":"` + seedHex + `"}`))
	}))
	defer srv.Close()

	src := &TEEMasterSeedSource{BaseURL: srv.URL, ServiceToken: "tok"}
	got, err := src.MasterSeed(context.Background())
	if err != nil {
		t.Fatalf("tee: %v", err)
	}
	if hex.EncodeToString(got) != seedHex {
		t.Fatalf("tee seed mismatch: %x", got)
	}
	// Bad token → non-200 error.
	if _, err := (&TEEMasterSeedSource{BaseURL: srv.URL, ServiceToken: "wrong"}).MasterSeed(context.Background()); err == nil {
		t.Fatal("bad token must error")
	}
	// Unconfigured → ErrMasterSeedNotConfigured.
	if _, err := (&TEEMasterSeedSource{}).MasterSeed(context.Background()); !errors.Is(err, ErrMasterSeedNotConfigured) {
		t.Fatal("empty TEE config must be ErrMasterSeedNotConfigured")
	}
}

// Compile-time: all three satisfy the port.
var (
	_ MasterSeedSource = StaticMasterSeedSource{}
	_ MasterSeedSource = EnvMasterSeedSource{}
	_ MasterSeedSource = (*TEEMasterSeedSource)(nil)
)
