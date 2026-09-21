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
	prefix string
}

// RedisOption configures a Redis store.
type RedisOption func(*redisStore)

// WithKeyPrefix prepends prefix to every key the store writes, so several
// applications can share one Redis database without seeing each other's
// sessions (and so an ACL rule like ~myapp:* can fence each of them in).
// The prefix is used verbatim — include the separator yourself:
// WithKeyPrefix("myapp:") gives myapp:session:{token}. Default: no prefix.
func WithKeyPrefix(prefix string) RedisOption {
	return func(s *redisStore) { s.prefix = prefix }
}

func NewRedisStore(opt *redis.Options, opts ...RedisOption) *redisStore {
	s := &redisStore{client: redis.NewClient(opt)}
	for _, o := range opts {
		o(s)
	}
	return s
}

func (s *redisStore) Close() error {
	return s.client.Close()
}

func (s *redisStore) ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), redisOpTimeout)
}

func (s *redisStore) key(token string) string {
	return s.prefix + "session:" + token
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

	return s.client.Set(ctx, s.key(session.Token), data, ttl).Err()
}

func (s *redisStore) Read(refreshToken string) (session sessions.Session, err error) {
	ctx, cancel := s.ctx()
	defer cancel()

	data, err := s.client.Get(ctx, s.key(refreshToken)).Bytes()
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
	return s.client.Del(ctx, s.key(refreshToken)).Err()
}
