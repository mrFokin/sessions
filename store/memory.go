package store

import (
	"sync"

	"github.com/golang-jwt/jwt/v5"
	"github.com/mrFokin/sessions/v2"
)

type memoryStore[C jwt.Claims] struct {
	sessions sync.Map
}

func NewMemoryStore[C jwt.Claims]() *memoryStore[C] {
	return &memoryStore[C]{}
}

func (m *memoryStore[C]) Create(s sessions.Session[C]) error {
	m.sessions.Store(s.Token, s)
	return nil
}

func (m *memoryStore[C]) Read(refreshToken string) (session sessions.Session[C], err error) {
	val, ok := m.sessions.Load(refreshToken)
	if !ok {
		err = sessions.ErrSessionNotFound
		return
	}
	session = val.(sessions.Session[C])
	return
}

func (m *memoryStore[C]) Delete(refreshToken string) error {
	m.sessions.Delete(refreshToken)
	return nil
}
