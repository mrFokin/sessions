package sessions_test

import (
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

// refreshApp mounts the API and the refresh route the way the README does, on a
// real router, so the redirect chain is checked without hand-built contexts
// (which is how the wildcard name mix-up used to go unnoticed).
func refreshApp(t *testing.T, refreshRoute string, opts ...sessions.RedirectOption) (*echo.Echo, string) {
	t.Helper()
	secret := []byte("secret")
	sm := sessions.New[jwt.MapClaims]("", secret, time.Minute, time.Hour, false, store.NewMemoryStore[jwt.MapClaims]())

	e := echo.New()
	e.POST(refreshRoute, sm.Refresh)
	api := e.Group("/api", sessions.JWTWithRedirect[jwt.MapClaims]("/auth/refresh", secret, opts...))
	api.POST("/rpc", func(c *echo.Context) error { return c.String(http.StatusOK, "ok") })
	return e, startSession(t, sm, jwt.MapClaims{"sub": "1"})
}

func post(e *echo.Echo, uri, sessionToken string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, uri, nil)
	if sessionToken != "" {
		req.AddCookie(&http.Cookie{Name: "session", Value: sessionToken})
	}
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}

func TestRefreshRoundTrip(t *testing.T) {
	testCases := []struct {
		name         string
		route        string
		opts         []sessions.RedirectOption
		wantRefresh  string
		wantLocation string
	}{
		{
			name:         "next param on a plain route",
			route:        "/auth/refresh",
			opts:         []sessions.RedirectOption{sessions.WithNextParam()},
			wantRefresh:  "/auth/refresh?next=%2Fapi%2Frpc%3Fq%3D1",
			wantLocation: "/api/rpc?q=1",
		},
		{
			name:         "default keeps the legacy wildcard route working",
			route:        "/auth/refresh/*uri",
			wantRefresh:  "/auth/refresh/api/rpc?q=1",
			wantLocation: "/api/rpc",
		},
		{
			name:         "next param also works on a legacy wildcard route",
			route:        "/auth/refresh/*uri",
			opts:         []sessions.RedirectOption{sessions.WithNextParam()},
			wantRefresh:  "/auth/refresh?next=%2Fapi%2Frpc%3Fq%3D1",
			wantLocation: "", // the wildcard route does not match a bare /auth/refresh
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			e, token := refreshApp(t, tc.route, tc.opts...)

			rec := post(e, "/api/rpc?q=1", "")
			require.Equal(t, http.StatusTemporaryRedirect, rec.Code)
			assert.Equal(t, tc.wantRefresh, rec.Header().Get("Location"))

			rec = post(e, rec.Header().Get("Location"), token)
			if tc.wantLocation == "" {
				assert.Equal(t, http.StatusNotFound, rec.Code)
				return
			}
			require.Equal(t, http.StatusTemporaryRedirect, rec.Code)
			assert.Equal(t, tc.wantLocation, rec.Header().Get("Location"))
		})
	}
}

func TestRefreshRejectsForeignNext(t *testing.T) {
	e, token := refreshApp(t, "/auth/refresh", sessions.WithNextParam())

	for _, next := range []string{
		"https://evil.com/x", "//evil.com", `/\evil.com`, "evil.com", "javascript:alert(1)",
	} {
		rec := post(e, "/auth/refresh?next="+next, token)
		assert.Equal(t, http.StatusBadRequest, rec.Code, "next=%q", next)
		assert.Empty(t, rec.Header().Get("Location"), "next=%q", next)
	}

	// a rejected redirect must not rotate the session
	rec := post(e, "/auth/refresh?next=%2Fapi%2Frpc", token)
	assert.Equal(t, http.StatusTemporaryRedirect, rec.Code)
}
