package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/mrFokin/sessions"
	"github.com/redis/go-redis/v9"
)

type redisStore struct {
	client *redis.Client
}

func NewRedisStore(opt *redis.Options) *redisStore {
	return &redisStore{
		client: redis.NewClient(opt),
	}
}

func (s *redisStore) Create(session sessions.Session) error {
	ctx := context.Background()

	data, err := json.Marshal(session)
	if err != nil {
		return err
	}

	ttl := time.Until(session.Expired)
	if ttl <= 0 {
		return nil
	}

	// Use the refresh token (session.Token) as the key
	return s.client.Set(ctx, "session:"+session.Token, data, ttl).Err()
}

func (s *redisStore) Read(refreshToken string) (session sessions.Session, err error) {
	ctx := context.Background()

	data, err := s.client.Get(ctx, "session:"+refreshToken).Bytes()
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
	ctx := context.Background()
	return s.client.Del(ctx, "session:"+refreshToken).Err()
}
