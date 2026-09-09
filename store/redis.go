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

// ErrNonPositiveTTL is returned by RedisStore.Create when Session.Expired
// is not in the future.
var ErrNonPositiveTTL = errors.New("session ttl must be positive")

// RedisStore is a Redis-backed SessionStore. Keys are session:{token} with TTL
// until Session.Expired.
type RedisStore[C jwt.Claims] struct {
	client *redis.Client
}

// NewRedisStore returns a RedisStore using opt. Call Close when finished.
func NewRedisStore[C jwt.Claims](opt *redis.Options) *RedisStore[C] {
	return &RedisStore[C]{
		client: redis.NewClient(opt),
	}
}

// Close closes the underlying Redis client.
func (s *RedisStore[C]) Close() error {
	return s.client.Close()
}

func (s *RedisStore[C]) ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), redisOpTimeout)
}

func sessionKey(token string) string {
	return "session:" + token
}

// Create stores session in Redis. It returns ErrNonPositiveTTL when
// Session.Expired is not in the future.
func (s *RedisStore[C]) Create(session sessions.Session[C]) error {
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

// Read loads a session by refresh token.
// It returns sessions.ErrSessionNotFound if the key is missing.
func (s *RedisStore[C]) Read(refreshToken string) (session sessions.Session[C], err error) {
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

// Delete removes a session by refresh token.
func (s *RedisStore[C]) Delete(refreshToken string) error {
	ctx, cancel := s.ctx()
	defer cancel()
	return s.client.Del(ctx, sessionKey(refreshToken)).Err()
}
