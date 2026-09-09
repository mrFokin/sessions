package sessions

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	echojwt "github.com/labstack/echo-jwt/v5"
	"github.com/labstack/echo/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockClaims struct {
	Name string `json:"Name"`
	jwt.RegisteredClaims
}

func TestJWTWithRedirect(t *testing.T) {
	testCases := []struct {
		when     string
		current  string
		path     string
		err      error
		redirect bool
		claims   *mockClaims
	}{
		{
			when:     "Нет cookie с access-токеном",
			path:     "/auth/refresh",
			redirect: true,
		},
		{
			when:    "Все в порядке",
			path:    "/auth/refresh",
			current: "access=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJOYW1lIjoiSmhvbiBEb2UifQ.hsShW3pRWuxeYtxaXf-igfnhexKQzoJqEl5zFjKyWl4",
			err:     nil,
			claims:  &mockClaims{Name: "Jhon Doe"},
		},
		{
			when:     "Нет cookie с access-токеном и есть префикс /api",
			path:     "/api/auth/refresh",
			redirect: true,
		},
	}

	e := echo.New()

	for _, tc := range testCases {
		t.Log(tc.when)

		h := JWTWithRedirect[jwt.MapClaims](tc.path, []byte("secret"))(func(c *echo.Context) error {
			return c.String(http.StatusOK, "test")
		})

		req := httptest.NewRequest(http.MethodPost, "/api/v2", nil)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		req.Header.Set(echo.HeaderCookie, tc.current)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := h(c)
		if tc.err != nil {
			assert.Error(t, err, "Ожидалась ошибка")
		} else if tc.redirect {
			assert.NoError(t, err, "Не должно быть ошибки при редиректе")
		} else {
			assert.Equal(t, tc.err, err, "Некорректный код ошибки обработчика")
		}

		if tc.redirect {
			assert.Equal(t, http.StatusTemporaryRedirect, rec.Code, "Некорректный http-статус ответа")
			expectedLocation := tc.path + "/api/v2"
			assert.Equal(t, expectedLocation, rec.Header().Get(echo.HeaderLocation), "Некорректный путь редиректа")
		} else {
			if tc.claims != nil {
				token, getErr := echo.ContextGet[*jwt.Token](c, "user")
				require.NoError(t, getErr)
				u := token.Claims.(jwt.MapClaims)
				assert.Equal(t, tc.claims.Name, u["Name"], "Некорректная информация о пользователе")
			}
		}
	}
}

func TestCloneAndSetExp(t *testing.T) {
	srcMap := jwt.MapClaims{"Name": "shared"}
	a, err := cloneAndSetExp(srcMap, time.Unix(1000, 0))
	require.NoError(t, err)
	b, err := cloneAndSetExp(srcMap, time.Unix(2000, 0))
	require.NoError(t, err)
	assert.Equal(t, "shared", srcMap["Name"])
	_, ok := srcMap["exp"]
	assert.False(t, ok)
	assert.EqualValues(t, int64(1000), a["exp"])
	assert.EqualValues(t, int64(2000), b["exp"])

	srcPtr := &mockClaims{Name: "shared"}
	p1, err := cloneAndSetExp(srcPtr, time.Unix(1000, 0))
	require.NoError(t, err)
	p2, err := cloneAndSetExp(srcPtr, time.Unix(2000, 0))
	require.NoError(t, err)
	assert.NotSame(t, p1, p2)
	assert.Nil(t, srcPtr.ExpiresAt)
	assert.Equal(t, "shared", p1.Name)
	assert.Equal(t, int64(1000), p1.ExpiresAt.Unix())
	assert.Equal(t, int64(2000), p2.ExpiresAt.Unix())
}

func TestNewClaims(t *testing.T) {
	m, err := newClaims[jwt.MapClaims]()
	require.NoError(t, err)
	assert.NotNil(t, m)

	p, err := newClaims[*mockClaims]()
	require.NoError(t, err)
	assert.NotNil(t, p)
	assert.Empty(t, p.Name)
}

func TestJWTWithRedirectTypedClaims(t *testing.T) {
	h := JWTWithRedirect[*mockClaims]("/auth/refresh", []byte("secret"))(func(c *echo.Context) error {
		return c.String(http.StatusOK, "test")
	})

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/v2", nil)
	req.Header.Set(echo.HeaderCookie, "access=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJOYW1lIjoiSmhvbiBEb2UifQ.hsShW3pRWuxeYtxaXf-igfnhexKQzoJqEl5zFjKyWl4")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := h(c)
	assert.NoError(t, err)

	token, getErr := echo.ContextGet[*jwt.Token](c, "user")
	require.NoError(t, getErr)
	u := token.Claims.(*mockClaims)
	assert.Equal(t, "Jhon Doe", u.Name)
}

func TestToken(t *testing.T) {
	claims := jwt.MapClaims{"Name": "Jhon Doe"}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("secret"))
	assert.NoError(t, err, "err")
	assert.Equal(t, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJOYW1lIjoiSmhvbiBEb2UifQ.hsShW3pRWuxeYtxaXf-igfnhexKQzoJqEl5zFjKyWl4", token, "token")

	config := echojwt.Config{
		NewClaimsFunc: func(c *echo.Context) jwt.Claims {
			return jwt.MapClaims{}
		},
		SigningKey:  []byte("secret"),
		TokenLookup: "cookie:access",
	}

	h := echojwt.WithConfig(config)(func(c *echo.Context) error {
		return c.String(http.StatusOK, "test")
	})

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/v2", nil)
	req.Header.Set(echo.HeaderCookie, "access=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJOYW1lIjoiSmhvbiBEb2UifQ.hsShW3pRWuxeYtxaXf-igfnhexKQzoJqEl5zFjKyWl4")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err = h(c)
	assert.NoError(t, err, "handler")

	tk, getErr := echo.ContextGet[*jwt.Token](c, "user")
	require.NoError(t, getErr)
	cl := tk.Claims.(jwt.MapClaims)
	assert.Equal(t, "Jhon Doe", cl["Name"], "claims")
}
