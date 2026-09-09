package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/mrFokin/sessions"
	"github.com/redis/go-redis/v9"
)

const redisOpTimeout = 3 * time.Second

var ErrNonPositiveTTL = errors.New("session ttl must be positive")

type redisStore struct {
	client *redis.Client
}

func NewRedisStore(opt *redis.Options) *redisStore {
	return &redisStore{
		client: redis.NewClient(opt),
	}
}

func (s *redisStore) Close() error {
	return s.client.Close()
}

func (s *redisStore) ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), redisOpTimeout)
}

func sessionKey(token string) string {
	return "session:" + token
}

func (s *redisStore) Create(session sessions.Session) error {
	ctx, cancel := s.ctx()
	defer cancel()

	data, err := json.Marshal(session)
	if err != nil {
		return err
	}

	ttl := time.Until(session.Expired)
	if ttl <= 0 {
		return ErrNonPositiveTTL
	}

	return s.client.Set(ctx, sessionKey(session.Token), data, ttl).Err()
}

func (s *redisStore) Read(refreshToken string) (session sessions.Session, err error) {
	ctx, cancel := s.ctx()
	defer cancel()

	data, err := s.client.Get(ctx, sessionKey(refreshToken)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			err = sessions.ErrSessionNotFound
			return
		}
		return
	}

	if err = json.Unmarshal(data, &session); err != nil {
		return
	}

	return
}

func (s *redisStore) Delete(refreshToken string) error {
	ctx, cancel := s.ctx()
	defer cancel()
	return s.client.Del(ctx, sessionKey(refreshToken)).Err()
}
