package store

import (
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/mrFokin/sessions/v2"
)

// MemoryStore is an in-memory SessionStore backed by sync.Map.
// Sessions are lost on process restart and are not shared across instances.
type MemoryStore[C jwt.Claims] struct {
	sessions sync.Map
	revoked  sync.Map // subject -> time.Time of the last RevokeUser
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
	if sub := subjectOf(session.Claims); sub != "" {
		if at, ok := m.revoked.Load(sub); ok && !session.Created.After(at.(time.Time)) {
			return sessions.Session[C]{}, sessions.ErrSessionNotFound
		}
	}
	return
}

// RevokeUser makes every session of subject created up to now unreadable.
// The revocation is kept for the life of the process, so ttl is ignored.
// It returns ErrEmptySubject for an empty subject.
func (m *MemoryStore[C]) RevokeUser(subject string, _ time.Duration) error {
	if subject == "" {
		return ErrEmptySubject
	}
	m.revoked.Store(subject, time.Now())
	return nil
}

// Delete removes a session by refresh token.
func (m *MemoryStore[C]) Delete(refreshToken string) error {
	m.sessions.Delete(refreshToken)
	return nil
}
