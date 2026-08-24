package store

import (
	"sync"

	"github.com/mrFokin/sessions"
)

type memoryStore struct {
	sessions sync.Map
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
	return
}

func (m *memoryStore) Delete(refreshToken string) error {
	m.sessions.Delete(refreshToken)
	return nil
}
