package sessions_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v5"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mrFokin/sessions/v2"
	"github.com/mrFokin/sessions/v2/store"
)

// refresh calls Refresh with the given refresh token and returns the status and
// the refresh token the response set (empty on 401).
func refresh(t *testing.T, sm sessions.Sessions[jwt.MapClaims], token string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: token})
	rec := httptest.NewRecorder()
	c := echo.New().NewContext(req, rec)
	c.SetPathValues(echo.PathValues{{Name: "uri", Value: "api"}})
	if err := sm.Refresh(c); err != nil {
		if errors.Is(err, echo.ErrUnauthorized) {
			return http.StatusUnauthorized, ""
		}
		t.Fatalf("Refresh: %v", err)
	}
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == "session" {
			return rec.Code, ck.Value
		}
	}
	return rec.Code, ""
}

func newRedisSessions(t *testing.T) (sessions.Sessions[jwt.MapClaims], *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	s := store.NewRedisStore[jwt.MapClaims](&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = s.Close() })
	return sessions.New[jwt.MapClaims]("", []byte("secret"), time.Minute, time.Hour, false, s), mr
}

func TestRefreshGrace(t *testing.T) {
	stores := map[string]func(t *testing.T) sessions.Sessions[jwt.MapClaims]{
		"memory": func(t *testing.T) sessions.Sessions[jwt.MapClaims] {
			return sessions.New[jwt.MapClaims]("", []byte("secret"), time.Minute, time.Hour, false, store.NewMemoryStore[jwt.MapClaims]())
		},
		"redis": func(t *testing.T) sessions.Sessions[jwt.MapClaims] {
			sm, _ := newRedisSessions(t)
			return sm
		},
	}

	for name, newSM := range stores {
		t.Run(name+"/old token yields the same successor", func(t *testing.T) {
			sm := newSM(t)
			old := startSession(t, sm, jwt.MapClaims{"sub": "42"})

			status, first := refresh(t, sm, old)
			require.Equal(t, http.StatusTemporaryRedirect, status)
			status, second := refresh(t, sm, old)
			require.Equal(t, http.StatusTemporaryRedirect, status, "a request that was in flight with the old token")
			assert.Equal(t, first, second, "no second rotation")

			status, _ = refresh(t, sm, first)
			assert.Equal(t, http.StatusTemporaryRedirect, status, "the successor keeps working")
		})

		t.Run(name+"/old token follows a double rotation", func(t *testing.T) {
			sm := newSM(t)
			old := startSession(t, sm, jwt.MapClaims{"sub": "42"})

			_, first := refresh(t, sm, old)
			_, second := refresh(t, sm, first)
			status, got := refresh(t, sm, old)
			require.Equal(t, http.StatusTemporaryRedirect, status)
			assert.Equal(t, second, got)
		})

		t.Run(name+"/revoked user loses the old token too", func(t *testing.T) {
			sm := newSM(t)
			old := startSession(t, sm, jwt.MapClaims{"sub": "42"})
			_, next := refresh(t, sm, old)

			require.NoError(t, sm.RevokeUser("42"))

			status, _ := refresh(t, sm, old)
			assert.Equal(t, http.StatusUnauthorized, status)
			status, _ = refresh(t, sm, next)
			assert.Equal(t, http.StatusUnauthorized, status)
		})

		t.Run(name+"/logout of the successor ends the old token", func(t *testing.T) {
			sm := newSM(t)
			old := startSession(t, sm, jwt.MapClaims{"sub": "42"})
			_, next := refresh(t, sm, old)

			req := httptest.NewRequest(http.MethodPost, "/", nil)
			req.AddCookie(&http.Cookie{Name: "session", Value: next})
			require.NoError(t, sm.Stop(echo.New().NewContext(req, httptest.NewRecorder())))

			status, _ := refresh(t, sm, old)
			assert.Equal(t, http.StatusUnauthorized, status)
		})
	}
}

func TestRefreshGraceExpires(t *testing.T) {
	sm, mr := newRedisSessions(t)
	old := startSession(t, sm, jwt.MapClaims{"sub": "42"})
	_, next := refresh(t, sm, old)

	mr.FastForward(31 * time.Second)

	status, _ := refresh(t, sm, old)
	assert.Equal(t, http.StatusUnauthorized, status)
	status, _ = refresh(t, sm, next)
	assert.Equal(t, http.StatusTemporaryRedirect, status, "the successor lives on")
}

// TestRefreshGraceConcurrent is the case the grace period exists for: several
// requests refresh with the same token at once, and none of them is rejected.
func TestRefreshGraceConcurrent(t *testing.T) {
	sm, _ := newRedisSessions(t)
	old := startSession(t, sm, jwt.MapClaims{"sub": "42"})

	const n = 8
	statuses := make([]int, n)
	tokens := make([]string, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() { statuses[i], tokens[i] = refresh(t, sm, old) })
	}
	wg.Wait()

	for i := range n {
		assert.Equal(t, http.StatusTemporaryRedirect, statuses[i], "request %d", i)
		status, _ := refresh(t, sm, tokens[i])
		assert.Equal(t, http.StatusTemporaryRedirect, status, "the token request %d got works", i)
	}
}
