package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/mrFokin/sessions/v2"
	"github.com/redis/go-redis/v9"
)

const redisOpTimeout = 3 * time.Second

var ErrNonPositiveTTL = errors.New("session ttl must be positive")

type redisStore[C jwt.Claims] struct {
	client *redis.Client
}

func NewRedisStore[C jwt.Claims](opt *redis.Options) *redisStore[C] {
	return &redisStore[C]{
		client: redis.NewClient(opt),
	}
}

func (s *redisStore[C]) Close() error {
	return s.client.Close()
}

func (s *redisStore[C]) ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), redisOpTimeout)
}

func sessionKey(token string) string {
	return "session:" + token
}

func (s *redisStore[C]) Create(session sessions.Session[C]) error {
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

func (s *redisStore[C]) Read(refreshToken string) (session sessions.Session[C], err error) {
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

func (s *redisStore[C]) Delete(refreshToken string) error {
	ctx, cancel := s.ctx()
	defer cancel()
	return s.client.Del(ctx, sessionKey(refreshToken)).Err()
}
