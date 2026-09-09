package sessions

import (
	"errors"
	"net/http"
	"reflect"

	"github.com/golang-jwt/jwt/v5"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
)

func JWTWithRedirect(path string, secret []byte, claims jwt.Claims) echo.MiddlewareFunc {
	return echojwt.WithConfig(echojwt.Config{
		TokenLookup: "cookie:access",
		SigningKey:  secret,
		NewClaimsFunc: func(c echo.Context) jwt.Claims {
			return cloneClaims(claims)
		},
		ErrorHandler: func(c echo.Context, err error) error {
			if errors.Is(err, echojwt.ErrJWTMissing) {
				return c.Redirect(http.StatusTemporaryRedirect, path+c.Request().RequestURI)
			}
			return err
		},
	})
}

func cloneClaims(claims jwt.Claims) jwt.Claims {
	switch claims.(type) {
	case nil:
		return jwt.MapClaims{}
	case jwt.MapClaims:
		return jwt.MapClaims{}
	case *jwt.MapClaims:
		m := jwt.MapClaims{}
		return &m
	}

	t := reflect.TypeOf(claims)
	if t.Kind() == reflect.Ptr {
		return reflect.New(t.Elem()).Interface().(jwt.Claims)
	}
	return reflect.New(t).Elem().Interface().(jwt.Claims)
}
