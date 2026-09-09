package sessions

import (
	"errors"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
	echojwt "github.com/labstack/echo-jwt/v5"
	"github.com/labstack/echo/v5"
)

// JWTWithRedirect returns Echo middleware that authenticates the access cookie
// and, if the cookie is missing, redirects 307 to path+RequestURI.
//
// path is the refresh URL including any prefix (for example /auth/refresh or
// /api/auth/refresh). C is allocated per request as the JWT claims type.
// A present but invalid token is not redirected; the JWT error is returned.
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
