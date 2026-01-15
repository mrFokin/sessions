package sessions

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

type mockClaims struct {
	Name string
	jwt.RegisteredClaims
}

func TestJWTWithRedirect(t *testing.T) {
	testCases := []struct {
		when     string
		current  string
		err      error
		redirect bool
		claims   *mockClaims
	}{
		{
			when:     "Нет cookie с access-токеном",
			redirect: true,
		},
		{
			when:    "Все в порядке",
			current: "access=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJOYW1lIjoiSmhvbiBEb2UifQ.hsShW3pRWuxeYtxaXf-igfnhexKQzoJqEl5zFjKyWl4",
			err:     nil,
			claims:  &mockClaims{Name: "Jhon Doe"},
		},
	}

	e := echo.New()

	h := JWTWithRedirect("/auth/refresh", []byte("secret"), jwt.MapClaims{})(func(c echo.Context) error {
		return c.String(http.StatusOK, "test")
	})

	for _, tc := range testCases {
		t.Log(tc.when)

		req := httptest.NewRequest(http.MethodPost, "/api/v2", nil)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		req.Header.Set(echo.HeaderCookie, tc.current)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := h(c)
		if tc.err != nil {
			assert.Error(t, err, "Ожидалась ошибка")
		} else if tc.redirect {
			// При редиректе ошибки быть не должно, но проверим статус
			assert.NoError(t, err, "Не должно быть ошибки при редиректе")
		} else {
			assert.Equal(t, tc.err, err, "Некорректный код ошибки обработчика")
		}

		if tc.redirect {
			assert.Equal(t, http.StatusTemporaryRedirect, rec.Code, "Некорректный http-статус ответа")
			assert.Equal(t, "/auth/refresh/api/v2", rec.Header().Get(echo.HeaderLocation), "Некорректный путь редиректа")
		} else {
			if tc.claims != nil {
				token := c.Get("user").(*jwt.Token)
				u := token.Claims.(jwt.MapClaims)
				assert.Equal(t, tc.claims.Name, u["Name"], "Некорректная информация о пользователе")
			}
		}
	}
}

func TestToken(t *testing.T) {
	claims := jwt.MapClaims{"Name": "Jhon Doe"}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("secret"))
	assert.NoError(t, err, "err")
	assert.Equal(t, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJOYW1lIjoiSmhvbiBEb2UifQ.hsShW3pRWuxeYtxaXf-igfnhexKQzoJqEl5zFjKyWl4", token, "token")

	config := echojwt.Config{
		NewClaimsFunc: func(c echo.Context) jwt.Claims {
			return jwt.MapClaims{}
		},
		SigningKey:  []byte("secret"),
		TokenLookup: "cookie:access",
	}

	h := echojwt.WithConfig(config)(func(c echo.Context) error {
		return c.String(http.StatusOK, "test")
	})

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/v2", nil)
	req.Header.Set(echo.HeaderCookie, "access=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJOYW1lIjoiSmhvbiBEb2UifQ.hsShW3pRWuxeYtxaXf-igfnhexKQzoJqEl5zFjKyWl4")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err = h(c)
	assert.NoError(t, err, "handler")

	tk := c.Get("user").(*jwt.Token)
	cl := tk.Claims.(jwt.MapClaims)
	assert.Equal(t, "Jhon Doe", cl["Name"], "claims")
}
