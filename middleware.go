package sessions

import (
	"errors"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
	echojwt "github.com/labstack/echo-jwt/v5"
	"github.com/labstack/echo/v5"
)

func JWTWithRedirect[C jwt.Claims](path string, secret []byte) echo.MiddlewareFunc {
	return echojwt.WithConfig(echojwt.Config{
		TokenLookup: "cookie:access",
		SigningKey:  secret,
		NewClaimsFunc: func(c *echo.Context) jwt.Claims {
			claims, err := newClaims[C]()
			if err != nil {
				return jwt.MapClaims{}
			}
			return claims
		},
		ErrorHandler: func(c *echo.Context, err error) error {
			if errors.Is(err, echojwt.ErrJWTMissing) {
				return c.Redirect(http.StatusTemporaryRedirect, path+c.Request().RequestURI)
			}
			return err
		},
	})
}
