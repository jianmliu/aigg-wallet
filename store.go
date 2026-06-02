package agentwallet

import (
	"context"
	"errors"
	"math/big"
	"sort"
	"strings"
	"sync"
)

// Authorization is one cached Permit2 PermitSingle authorization. Row identity
// is (Owner, Agent, Token, Nonce). The consumer's "subject" (user_id / npcId)
// is NOT modelled here — map it in your own store impl if you need it.
type Authorization struct {
	Owner         string // EIP-55 main wallet that signed the PermitSingle
	Agent         string // spender (the agent EOA)
	Token         string // ERC-20
	AmountAtoms   string // permit2 allowance (uint256 decimal)
	Expiration    int64  // uint48 unix ts
	Nonce         int64  // uint48 (Permit2 AllowanceTransfer sequential nonce)
	SignatureHex  string // 0x 65-byte; "" for event-sourced rows (not spendable)
	SpentAtoms    string // cumulative spent, decimal; "" treated as "0"
	Revoked       bool   // app-level revoke
	OnchainLocked bool   // Permit2 Lockdown observed
	CreatedAtUnix int64  // for "most recent" ordering
}

func (a *Authorization) spent() *big.Int {
	v, ok := new(big.Int).SetString(orZero(a.SpentAtoms), 10)
	if !ok {
		return big.NewInt(0)
	}
	return v
}

func orZero(s string) string {
	if strings.TrimSpace(s) == "" {
		return "0"
	}
	return s
}

// Sentinels.
var (
	ErrNoAuthorization               = errors.New("agentwallet: no active authorization")
	ErrAuthorizationMissingSignature = errors.New("agentwallet: authorization missing signature (re-authorize)")
)

// AuthorizationStore is the persistence port. Implement over your DB; a
// MemoryStore is provided for tests / simple deployments.
type AuthorizationStore interface {
	// Upsert is idempotent on (Owner, Agent, Token, Nonce). existed=true when
	// a row with that identity was already present (no-op / fields refreshed).
	Upsert(ctx context.Context, a Authorization) (existed bool, err error)
	// ActiveForAgent returns the most-recently-created authorization for the
	// agent EOA that is not revoked, not locked, expiration > now, and has a
	// signature. ErrNoAuthorization / ErrAuthorizationMissingSignature else.
	ActiveForAgent(ctx context.Context, agent string, now int64) (*Authorization, error)
	// ActiveForOwner is the same but keyed by (owner, token) — used by the
	// Transfer-event reconciler.
	ActiveForOwner(ctx context.Context, owner, token string, now int64) (*Authorization, error)
	// BumpSpent adds addAtoms (decimal) to (owner, agent, token, nonce).
	BumpSpent(ctx context.Context, owner, agent, token string, nonce int64, addAtoms string) error
	// MarkLocked sets OnchainLocked on every (owner, agent, token) row.
	MarkLocked(ctx context.Context, owner, agent, token string) error
}

// MemoryStore is a thread-safe in-memory AuthorizationStore.
type MemoryStore struct {
	mu   sync.Mutex
	rows []Authorization
}

// NewMemoryStore returns an empty in-memory store.
func NewMemoryStore() *MemoryStore { return &MemoryStore{} }

func idMatch(a Authorization, owner, agent, token string, nonce int64) bool {
	return strings.EqualFold(a.Owner, owner) && strings.EqualFold(a.Agent, agent) &&
		strings.EqualFold(a.Token, token) && a.Nonce == nonce
}

func (m *MemoryStore) Upsert(_ context.Context, a Authorization) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.rows {
		if idMatch(m.rows[i], a.Owner, a.Agent, a.Token, a.Nonce) {
			// Preserve accumulated spend; refresh the rest.
			a.SpentAtoms = orZero(m.rows[i].SpentAtoms)
			if a.CreatedAtUnix == 0 {
				a.CreatedAtUnix = m.rows[i].CreatedAtUnix
			}
			m.rows[i] = a
			return true, nil
		}
	}
	if a.SpentAtoms == "" {
		a.SpentAtoms = "0"
	}
	m.rows = append(m.rows, a)
	return false, nil
}

func (m *MemoryStore) pickActive(pred func(Authorization) bool, requireSig bool) (*Authorization, error) {
	var cands []Authorization
	for _, r := range m.rows {
		if r.Revoked || r.OnchainLocked {
			continue
		}
		if pred(r) {
			cands = append(cands, r)
		}
	}
	if len(cands) == 0 {
		return nil, ErrNoAuthorization
	}
	sort.SliceStable(cands, func(i, j int) bool { return cands[i].CreatedAtUnix > cands[j].CreatedAtUnix })
	if requireSig {
		for i := range cands {
			if strings.TrimSpace(cands[i].SignatureHex) != "" {
				c := cands[i]
				return &c, nil
			}
		}
		return nil, ErrAuthorizationMissingSignature
	}
	c := cands[0]
	return &c, nil
}

func (m *MemoryStore) ActiveForAgent(_ context.Context, agent string, now int64) (*Authorization, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.pickActive(func(r Authorization) bool {
		return strings.EqualFold(r.Agent, agent) && r.Expiration > now
	}, true)
}

func (m *MemoryStore) ActiveForOwner(_ context.Context, owner, token string, now int64) (*Authorization, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.pickActive(func(r Authorization) bool {
		return strings.EqualFold(r.Owner, owner) && strings.EqualFold(r.Token, token) && r.Expiration > now
	}, false)
}

func (m *MemoryStore) BumpSpent(_ context.Context, owner, agent, token string, nonce int64, addAtoms string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	add, ok := new(big.Int).SetString(strings.TrimSpace(addAtoms), 10)
	if !ok {
		return errors.New("agentwallet store: bad addAtoms")
	}
	for i := range m.rows {
		if idMatch(m.rows[i], owner, agent, token, nonce) {
			cur, _ := new(big.Int).SetString(orZero(m.rows[i].SpentAtoms), 10)
			m.rows[i].SpentAtoms = new(big.Int).Add(cur, add).String()
			return nil
		}
	}
	return ErrNoAuthorization
}

func (m *MemoryStore) MarkLocked(_ context.Context, owner, agent, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.rows {
		if strings.EqualFold(m.rows[i].Owner, owner) && strings.EqualFold(m.rows[i].Agent, agent) &&
			strings.EqualFold(m.rows[i].Token, token) {
			m.rows[i].OnchainLocked = true
		}
	}
	return nil
}

var _ AuthorizationStore = (*MemoryStore)(nil)
