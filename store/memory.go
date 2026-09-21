package store

import (
	"sync"
	"time"

	"github.com/mrFokin/sessions"
)

type memoryStore struct {
	sessions sync.Map
	revoked  sync.Map // subject -> time.Time of the last RevokeUser
}

func NewMemoryStore() *memoryStore {
	return &memoryStore{}
}

func (m *memoryStore) Create(s sessions.Session) error {
	m.sessions.Store(s.Token, s)
	return nil
}

func (m *memoryStore) Read(refreshToken string) (session sessions.Session, err error) {
	val, ok := m.sessions.Load(refreshToken)
	if !ok {
		err = sessions.ErrSessionNotFound
		return
	}
	session = val.(sessions.Session)
	if sub, _ := session.Claims.GetSubject(); sub != "" {
		if at, ok := m.revoked.Load(sub); ok && !session.Created.After(at.(time.Time)) {
			return sessions.Session{}, sessions.ErrSessionNotFound
		}
	}
	return
}

// RevokeUser makes every session of subject created up to now unreadable.
// The revocation is kept for the life of the process, so ttl is ignored.
func (m *memoryStore) RevokeUser(subject string, _ time.Duration) error {
	if subject == "" {
		return ErrEmptySubject
	}
	m.revoked.Store(subject, time.Now())
	return nil
}

func (m *memoryStore) Delete(refreshToken string) error {
	m.sessions.Delete(refreshToken)
	return nil
}
