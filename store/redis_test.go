package store

import (
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/mrFokin/sessions"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestRedis(t testing.TB) (*redisStore, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	s := NewRedisStore(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = s.Close() })
	return s, mr
}

func testSession(token string, ttl time.Duration) sessions.Session {
	now := time.Now()
	return sessions.Session{
		Token: token,
		Claims: jwt.MapClaims{
			"user_id": "123",
			"email":   "test@example.com",
		},
		Device: sessions.Device{
			IP:        "127.0.0.1",
			UserAgent: "Mozilla/5.0",
		},
		Created: now,
		Expired: now.Add(ttl),
	}
}

func TestRedisStore_CreateReadDelete(t *testing.T) {
	s, mr := newTestRedis(t)
	session := testSession("redis-token-123", time.Hour)

	require.NoError(t, s.Create(session))
	assert.True(t, mr.Exists("session:"+session.Token))

	got, err := s.Read(session.Token)
	require.NoError(t, err)
	assert.Equal(t, session.Token, got.Token)
	assert.Equal(t, session.Claims["user_id"], got.Claims["user_id"])
	assert.Equal(t, session.Device.IP, got.Device.IP)

	require.NoError(t, s.Delete(session.Token))
	assert.False(t, mr.Exists("session:"+session.Token))
}

func TestRedisStore_ReadNonExisting(t *testing.T) {
	s, _ := newTestRedis(t)
	_, err := s.Read("missing")
	assert.ErrorIs(t, err, sessions.ErrSessionNotFound)
}

func TestRedisStore_DeleteNonExisting(t *testing.T) {
	s, _ := newTestRedis(t)
	assert.NoError(t, s.Delete("missing"))
}

func TestRedisStore_CreateExpired(t *testing.T) {
	s, mr := newTestRedis(t)
	session := testSession("expired-token", -time.Hour)

	err := s.Create(session)
	assert.ErrorIs(t, err, ErrNonPositiveTTL)
	assert.False(t, mr.Exists("session:"+session.Token))
}

func TestRedisStore_TTLExpiration(t *testing.T) {
	s, mr := newTestRedis(t)
	session := testSession("short-lived-token", 2*time.Second)

	require.NoError(t, s.Create(session))
	assert.True(t, mr.Exists("session:"+session.Token))

	mr.FastForward(3 * time.Second)

	assert.False(t, mr.Exists("session:"+session.Token))
	_, err := s.Read(session.Token)
	assert.ErrorIs(t, err, sessions.ErrSessionNotFound)
}

func TestRedisStore_Close(t *testing.T) {
	mr := miniredis.RunT(t)
	s := NewRedisStore(&redis.Options{Addr: mr.Addr()})
	require.NoError(t, s.Close())
	err := s.Create(testSession("after-close", time.Hour))
	assert.Error(t, err)
}

func BenchmarkRedisStore_Create(b *testing.B) {
	s, _ := newTestRedis(b)
	session := testSession("benchmark-token", time.Hour)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		session.Token = "benchmark-token-" + itoa(i)
		s.Create(session)
	}
}

func BenchmarkRedisStore_Read(b *testing.B) {
	s, _ := newTestRedis(b)
	session := testSession("benchmark-read-token", time.Hour)
	require.NoError(b, s.Create(session))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Read(session.Token)
	}
}

func BenchmarkRedisStore_Delete(b *testing.B) {
	s, _ := newTestRedis(b)
	for i := 0; i < b.N; i++ {
		session := testSession("benchmark-delete-token-"+itoa(i), time.Hour)
		s.Create(session)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Delete("benchmark-delete-token-" + itoa(i))
	}
}
