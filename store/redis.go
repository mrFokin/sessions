package store

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/mrFokin/sessions"
	"github.com/redis/go-redis/v9"
)

const redisOpTimeout = 3 * time.Second

var ErrNonPositiveTTL = errors.New("session ttl must be positive")

// ErrEmptySubject is returned by RevokeUser for an empty subject.
var ErrEmptySubject = errors.New("subject must not be empty")

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

func (s *redisStore) revokedKey(subject string) string {
	return s.prefix + "revoked:" + subject
}

// RevokeUser makes every session of subject (its "sub" claim) created up to now
// unreadable by recording the time under {prefix}revoked:{subject} for ttl.
// Read compares it with Session.Created, so nothing is enumerated or deleted
// here and sessions started later are unaffected.
func (s *redisStore) RevokeUser(subject string, ttl time.Duration) error {
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
func (s *redisStore) revoked(ctx context.Context, session sessions.Session) (bool, error) {
	sub, _ := session.Claims.GetSubject()
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

	gone, err := s.revoked(ctx, session)
	if err != nil {
		return sessions.Session{}, err
	}
	if gone {
		return sessions.Session{}, sessions.ErrSessionNotFound
	}

	return
}

func (s *redisStore) Delete(refreshToken string) error {
	ctx, cancel := s.ctx()
	defer cancel()
	return s.client.Del(ctx, s.key(refreshToken)).Err()
}
