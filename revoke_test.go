package sessions_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mrFokin/sessions/v2"
	"github.com/mrFokin/sessions/v2/store"
)

func startSession(t *testing.T, sm sessions.Sessions[jwt.MapClaims], claims jwt.MapClaims) string {
	t.Helper()
	rec := httptest.NewRecorder()
	c := echo.New().NewContext(httptest.NewRequest(http.MethodPost, "/auth", nil), rec)
	require.NoError(t, sm.Start(c, claims))
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == "session" {
			return ck.Value
		}
	}
	t.Fatal("no session cookie")
	return ""
}

func refreshStatus(t *testing.T, sm sessions.Sessions[jwt.MapClaims], token string) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: token})
	rec := httptest.NewRecorder()
	c := echo.New().NewContext(req, rec)
	c.SetPath("/auth/refresh/*uri")
	c.SetPathValues(echo.PathValues{{Name: "uri", Value: "api"}})
	if err := sm.Refresh(c); err != nil {
		if errors.Is(err, echo.ErrUnauthorized) {
			return http.StatusUnauthorized
		}
		t.Fatalf("Refresh: %v", err)
	}
	return rec.Code
}

func TestRevokeUserEndToEnd(t *testing.T) {
	sm := sessions.New[jwt.MapClaims]("", []byte("secret"), time.Minute, time.Hour, false, store.NewMemoryStore[jwt.MapClaims]())

	phone := startSession(t, sm, jwt.MapClaims{"sub": "42"})
	laptop := startSession(t, sm, jwt.MapClaims{"sub": "42"})
	stranger := startSession(t, sm, jwt.MapClaims{"sub": "7"})

	require.NoError(t, sm.RevokeUser("42"))

	assert.Equal(t, http.StatusUnauthorized, refreshStatus(t, sm, phone))
	assert.Equal(t, http.StatusUnauthorized, refreshStatus(t, sm, laptop))
	assert.Equal(t, http.StatusTemporaryRedirect, refreshStatus(t, sm, stranger), "other users keep their sessions")

	time.Sleep(2 * time.Millisecond) // the new session must be created strictly after the revocation
	relogin := startSession(t, sm, jwt.MapClaims{"sub": "42"})
	assert.Equal(t, http.StatusTemporaryRedirect, refreshStatus(t, sm, relogin), "a session started after the revocation works")
}
