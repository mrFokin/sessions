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

func TestRedisStore_KeyPrefix(t *testing.T) {
	mr := miniredis.RunT(t)
	s := NewRedisStore(&redis.Options{Addr: mr.Addr()}, WithKeyPrefix("app:"))
	t.Cleanup(func() { _ = s.Close() })

	session := testSession("prefixed", time.Minute)
	require.NoError(t, s.Create(session))
	assert.True(t, mr.Exists("app:session:"+session.Token))
	assert.False(t, mr.Exists("session:"+session.Token))

	got, err := s.Read(session.Token)
	require.NoError(t, err)
	assert.Equal(t, session.Token, got.Token)

	require.NoError(t, s.Delete(session.Token))
	assert.False(t, mr.Exists("app:session:"+session.Token))
}

func TestRedisStore_PrefixesIsolateStores(t *testing.T) {
	mr := miniredis.RunT(t)
	a := NewRedisStore(&redis.Options{Addr: mr.Addr()}, WithKeyPrefix("a:"))
	b := NewRedisStore(&redis.Options{Addr: mr.Addr()}, WithKeyPrefix("b:"))
	plain := NewRedisStore(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = a.Close(); _ = b.Close(); _ = plain.Close() })

	session := testSession("shared-token", time.Minute)
	require.NoError(t, a.Create(session))

	_, err := b.Read(session.Token)
	assert.ErrorIs(t, err, sessions.ErrSessionNotFound)
	_, err = plain.Read(session.Token)
	assert.ErrorIs(t, err, sessions.ErrSessionNotFound)

	// Deleting through another store's namespace must not touch a's session.
	require.NoError(t, b.Delete(session.Token))
	_, err = a.Read(session.Token)
	assert.NoError(t, err)
}

func sessionFor(token, sub string, created time.Time) sessions.Session {
	s := testSession(token, time.Hour)
	s.Claims["sub"] = sub
	s.Created = created
	return s
}

func TestRedisStore_RevokeUser(t *testing.T) {
	s, mr := newTestRedis(t)
	now := time.Now()

	old := sessionFor("old", "42", now.Add(-time.Minute))
	other := sessionFor("other", "7", now.Add(-time.Minute))
	noSub := testSession("no-sub", time.Hour)
	for _, sess := range []sessions.Session{old, other, noSub} {
		require.NoError(t, s.Create(sess))
	}

	require.NoError(t, s.RevokeUser("42", time.Hour))
	assert.True(t, mr.Exists("revoked:42"))
	assert.Equal(t, time.Hour, mr.TTL("revoked:42"))

	_, err := s.Read(old.Token)
	assert.ErrorIs(t, err, sessions.ErrSessionNotFound, "session created before the revocation must be gone")

	_, err = s.Read(other.Token)
	assert.NoError(t, err, "another subject is unaffected")
	_, err = s.Read(noSub.Token)
	assert.NoError(t, err, "a session without a subject is unaffected")

	// A session started after the revocation (e.g. login with the new password) works.
	fresh := sessionFor("fresh", "42", time.Now().Add(time.Minute))
	require.NoError(t, s.Create(fresh))
	_, err = s.Read(fresh.Token)
	assert.NoError(t, err)
}

func TestRedisStore_RevokeUserValidatesArguments(t *testing.T) {
	s, _ := newTestRedis(t)

	assert.ErrorIs(t, s.RevokeUser("", time.Hour), ErrEmptySubject)
	assert.ErrorIs(t, s.RevokeUser("42", 0), ErrNonPositiveTTL)
}

func TestRedisStore_RevokeUserUsesKeyPrefix(t *testing.T) {
	mr := miniredis.RunT(t)
	a := NewRedisStore(&redis.Options{Addr: mr.Addr()}, WithKeyPrefix("a:"))
	b := NewRedisStore(&redis.Options{Addr: mr.Addr()}, WithKeyPrefix("b:"))
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })

	sessA := sessionFor("tok-a", "42", time.Now().Add(-time.Minute))
	sessB := sessionFor("tok-b", "42", time.Now().Add(-time.Minute))
	require.NoError(t, a.Create(sessA))
	require.NoError(t, b.Create(sessB))

	require.NoError(t, a.RevokeUser("42", time.Hour))
	assert.True(t, mr.Exists("a:revoked:42"))
	assert.False(t, mr.Exists("revoked:42"))

	_, err := a.Read(sessA.Token)
	assert.ErrorIs(t, err, sessions.ErrSessionNotFound)
	_, err = b.Read(sessB.Token)
	assert.NoError(t, err, "revoking in one namespace must not touch another")
}

func TestRedisStore_RevocationExpires(t *testing.T) {
	s, mr := newTestRedis(t)
	require.NoError(t, s.RevokeUser("42", time.Minute))

	mr.FastForward(2 * time.Minute)
	assert.False(t, mr.Exists("revoked:42"))
}
