package store

import (
	"sync"

	"github.com/golang-jwt/jwt/v5"
	"github.com/mrFokin/sessions/v2"
)

// MemoryStore is an in-memory SessionStore backed by sync.Map.
// Sessions are lost on process restart and are not shared across instances.
type MemoryStore[C jwt.Claims] struct {
	sessions sync.Map
}

// NewMemoryStore returns an empty MemoryStore.
func NewMemoryStore[C jwt.Claims]() *MemoryStore[C] {
	return &MemoryStore[C]{}
}

// Create stores session keyed by session.Token.
func (m *MemoryStore[C]) Create(s sessions.Session[C]) error {
	m.sessions.Store(s.Token, s)
	return nil
}

// Read loads a session by refresh token.
// It returns sessions.ErrSessionNotFound if the session does not exist.
func (m *MemoryStore[C]) Read(refreshToken string) (session sessions.Session[C], err error) {
	val, ok := m.sessions.Load(refreshToken)
	if !ok {
		err = sessions.ErrSessionNotFound
		return
	}
	session = val.(sessions.Session[C])
	return
}

// Delete removes a session by refresh token.
func (m *MemoryStore[C]) Delete(refreshToken string) error {
	m.sessions.Delete(refreshToken)
	return nil
}
