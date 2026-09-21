package sessions_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mrFokin/sessions"
	"github.com/mrFokin/sessions/store"
)

func startSession(t *testing.T, sm sessions.Sessions, claims jwt.MapClaims) string {
	t.Helper()
	e := echo.New()
	rec := httptest.NewRecorder()
	c := e.NewContext(httptest.NewRequest(http.MethodPost, "/auth", nil), rec)
	require.NoError(t, sm.Start(c, claims))
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == "session" {
			return ck.Value
		}
	}
	t.Fatal("no session cookie")
	return ""
}

func refreshStatus(t *testing.T, sm sessions.Sessions, token string) int {
	t.Helper()
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: token})
	c := e.NewContext(req, httptest.NewRecorder())
	c.SetPath("/auth/refresh/*uri")
	c.SetParamNames("uri")
	c.SetParamValues("api")
	if err := sm.Refresh(c); err != nil {
		if he, ok := err.(*echo.HTTPError); ok {
			return he.Code
		}
		t.Fatalf("Refresh: %v", err)
	}
	return c.Response().Status
}

func TestRevokeUserEndToEnd(t *testing.T) {
	sm := sessions.New("", []byte("secret"), time.Minute, time.Hour, false, store.NewMemoryStore())

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
