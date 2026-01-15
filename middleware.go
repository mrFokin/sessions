package sessions

import (
	"errors"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
)

func JWTWithRedirect(path string, secret []byte, claims jwt.Claims) echo.MiddlewareFunc {
	return echojwt.WithConfig(echojwt.Config{
		TokenLookup: "cookie:access",
		SigningKey:  secret,
		NewClaimsFunc: func(c echo.Context) jwt.Claims {
			return claims
		},
		ErrorHandler: func(c echo.Context, err error) error {
			if errors.Is(err, echojwt.ErrJWTMissing) {
				return c.Redirect(http.StatusTemporaryRedirect, path+c.Request().RequestURI)
			}
			return err
		},
	})
}
