package store

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/mrFokin/sessions/v2"
	"github.com/redis/go-redis/v9"
)

const redisOpTimeout = 3 * time.Second

// ErrNonPositiveTTL is returned by RedisStore.Create when Session.Expired
// is not in the future.
var ErrNonPositiveTTL = errors.New("session ttl must be positive")

// ErrEmptySubject is returned by RevokeUser for an empty subject.
var ErrEmptySubject = errors.New("subject must not be empty")

// RedisStore is a Redis-backed SessionStore. Keys are {prefix}session:{token}
// (no prefix unless WithKeyPrefix is given) with TTL until Session.Expired.
type RedisStore[C jwt.Claims] struct {
	client *redis.Client
	prefix string
}

// redisConfig collects the settings a RedisOption can change.
type redisConfig struct {
	prefix string
}

// RedisOption configures a RedisStore.
type RedisOption func(*redisConfig)

// WithKeyPrefix prepends prefix to every key the store writes, so several
// applications can share one Redis database without seeing each other's
// sessions (and so an ACL rule like ~myapp:* can fence each of them in).
// The prefix is used verbatim — include the separator yourself:
// WithKeyPrefix("myapp:") gives myapp:session:{token}. Default: no prefix.
func WithKeyPrefix(prefix string) RedisOption {
	return func(c *redisConfig) { c.prefix = prefix }
}

// NewRedisStore returns a RedisStore using opt. Call Close when finished.
func NewRedisStore[C jwt.Claims](opt *redis.Options, opts ...RedisOption) *RedisStore[C] {
	var cfg redisConfig
	for _, o := range opts {
		o(&cfg)
	}
	return &RedisStore[C]{
		client: redis.NewClient(opt),
		prefix: cfg.prefix,
	}
}

// Close closes the underlying Redis client.
func (s *RedisStore[C]) Close() error {
	return s.client.Close()
}

func (s *RedisStore[C]) ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), redisOpTimeout)
}

func (s *RedisStore[C]) key(token string) string {
	return s.prefix + "session:" + token
}

func (s *RedisStore[C]) revokedKey(subject string) string {
	return s.prefix + "revoked:" + subject
}

// RevokeUser makes every session of subject (its "sub" claim) created up to now
// unreadable by recording the time under {prefix}revoked:{subject} for ttl.
// Read compares it with Session.Created, so nothing is enumerated or deleted
// here and sessions started later are unaffected. It returns ErrEmptySubject
// for an empty subject and ErrNonPositiveTTL when ttl is not positive.
func (s *RedisStore[C]) RevokeUser(subject string, ttl time.Duration) error {
	if subject == "" {
		return ErrEmptySubject
	}
	if ttl <= 0 {
		return ErrNonPositiveTTL
	}

	ctx, cancel := s.ctx()
	defer cancel()
	stamp := strconv.FormatInt(time.Now().UnixNano(), 10)
	return s.client.Set(ctx, s.revokedKey(subject), stamp, ttl).Err()
}

// revoked reports whether session was created at or before its subject's last
// RevokeUser.
func (s *RedisStore[C]) revoked(ctx context.Context, session sessions.Session[C]) (bool, error) {
	sub := subjectOf(session.Claims)
	if sub == "" {
		return false, nil
	}
	raw, err := s.client.Get(ctx, s.revokedKey(sub)).Result()
	if errors.Is(err, redis.Nil) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	nanos, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return false, err
	}
	return !session.Created.After(time.Unix(0, nanos)), nil
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

	return s.client.Set(ctx, s.key(session.Token), data, ttl).Err()
}

// Read loads a session by refresh token.
// It returns sessions.ErrSessionNotFound if the key is missing.
func (s *RedisStore[C]) Read(refreshToken string) (session sessions.Session[C], err error) {
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

	gone, err := s.revoked(ctx, session)
	if err != nil {
		return sessions.Session[C]{}, err
	}
	if gone {
		return sessions.Session[C]{}, sessions.ErrSessionNotFound
	}

	return
}

// Delete removes a session by refresh token.
func (s *RedisStore[C]) Delete(refreshToken string) error {
	ctx, cancel := s.ctx()
	defer cancel()
	return s.client.Del(ctx, s.key(refreshToken)).Err()
}
