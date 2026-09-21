package sessions

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/golang-jwt/jwt/v5"
	echojwt "github.com/labstack/echo-jwt/v5"
	"github.com/labstack/echo/v5"
)

// RedirectOption configures JWTWithRedirect.
type RedirectOption func(*redirectConfig)

type redirectConfig struct {
	nextParam bool
}

// WithNextParam makes JWTWithRedirect carry the original request URI in the
// "next" query parameter of the refresh URL (path?next=%2Fapi%3Fq%3D1) instead
// of appending it to the path (path/api). The refresh route can then be a plain
// POST {prefix}/auth/refresh with no wildcard, and the query string of the
// original request survives the round trip. Sessions.Refresh understands both
// forms; the default stays the path form so existing routes keep working.
func WithNextParam() RedirectOption {
	return func(c *redirectConfig) { c.nextParam = true }
}

// JWTWithRedirect returns Echo middleware that authenticates the access cookie
// and, if the cookie is missing, redirects 307 to path+RequestURI (or, with
// WithNextParam, to path?next=RequestURI).
//
// path is the refresh URL including any prefix (for example /auth/refresh or
// /api/auth/refresh). C is allocated per request as the JWT claims type.
// A present but invalid token is not redirected; the JWT error is returned.
func JWTWithRedirect[C jwt.Claims](path string, secret []byte, opts ...RedirectOption) echo.MiddlewareFunc {
	var cfg redirectConfig
	for _, o := range opts {
		o(&cfg)
	}
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
				uri := c.Request().RequestURI
				if cfg.nextParam {
					return c.Redirect(http.StatusTemporaryRedirect, path+"?next="+url.QueryEscape(uri))
				}
				return c.Redirect(http.StatusTemporaryRedirect, path+uri)
			}
			return err
		},
	})
}
