package sessions

import (
	"errors"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/labstack/echo/v5"
)

// ErrSessionNotFound is returned by SessionStore.Read when no session exists
// for the given refresh token.
var (
	ErrSessionNotFound = errors.New("session not found")
)

// Sessions manages cookie-based user sessions for an Echo application.
type Sessions[C jwt.Claims] interface {
	// Start creates a new session, replacing any existing session cookie.
	// It issues a JWT access cookie and an HttpOnly refresh cookie named session.
	Start(c *echo.Context, claims C) error
	// Stop deletes the current session from the store and clears both cookies.
	Stop(c *echo.Context) error
	// Refresh rotates the session using the refresh cookie and redirects 307
	// to the same-origin path in the *uri route parameter.
	Refresh(c *echo.Context) error
}

// SessionStore persists sessions keyed by refresh token.
type SessionStore[C jwt.Claims] interface {
	// Create stores a session. RedisStore requires a positive TTL
	// (Session.Expired in the future).
	Create(Session[C]) error
	// Read loads a session by refresh token.
	// It returns ErrSessionNotFound if the session does not exist.
	Read(refreshToken string) (Session[C], error)
	// Delete removes a session by refresh token.
	Delete(refreshToken string) error
}

// Device is the client fingerprint captured at session creation.
type Device struct {
	IP        string // client address from Echo RealIP
	UserAgent string // request User-Agent
}

// Session is a stored refresh session.
type Session[C jwt.Claims] struct {
	Token   string    // refresh token (UUID)
	Claims  C         // JWT claims copied into the access token
	Device  Device    // client captured at Start
	Created time.Time // session creation time
	Expired time.Time // refresh expiry; used as Redis TTL
}

// New returns a session manager.
//
// prefix is the cookie path prefix ("" for the site root). A non-empty value
// without a leading slash is normalized (api → /api); a trailing slash is
// stripped. The session cookie path is {prefix}/auth; the access cookie path
// is {prefix} or / when prefix is empty.
//
// secret signs JWTs. accessTimeout and refreshTimeout set cookie and token
// lifetimes. secure sets the Secure flag (true for HTTPS). store persists
// refresh sessions.
func New[C jwt.Claims](prefix string, secret []byte, accessTimeout time.Duration, refreshTimeout time.Duration, secure bool, store SessionStore[C]) Sessions[C] {
	return &sessions[C]{
		Prefix:         normalizePrefix(prefix),
		Secret:         secret,
		AccessTimeout:  accessTimeout,
		RefreshTimeout: refreshTimeout,
		Secure:         secure,
		Store:          store,
	}
}

func normalizePrefix(prefix string) string {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" || prefix == "/" {
		return ""
	}
	prefix = strings.TrimRight(prefix, "/")
	if !strings.HasPrefix(prefix, "/") {
		prefix = "/" + prefix
	}
	return prefix
}

type sessions[C jwt.Claims] struct {
	Prefix         string
	Secret         []byte
	AccessTimeout  time.Duration
	RefreshTimeout time.Duration
	Secure         bool
	Store          SessionStore[C]
}

func (s *sessions[C]) Start(c *echo.Context, claims C) error {
	current, err := c.Cookie("session")
	if err == nil && current != nil {
		if err := s.Store.Delete(current.Value); err != nil {
			c.Logger().Info("Sessions.Start: Ошибка удаления сессии из SessionStore")
		}
	}

	if err := s.start(c, claims); err != nil {
		s.clearCookies(c)
		return err
	}
	return nil
}

func (s *sessions[C]) Stop(c *echo.Context) error {
	current, err := c.Cookie("session")
	if err == nil && current != nil {
		if err := s.Store.Delete(current.Value); err != nil {
			c.Logger().Info("Sessions.Stop: Ошибка удаления сессии из SessionStore")
		}
	}

	s.clearCookies(c)
	return nil
}

func (s *sessions[C]) Refresh(c *echo.Context) error {
	cookie, err := c.Cookie("session")
	if err != nil || cookie == nil {
		return echo.ErrUnauthorized
	}

	current, err := s.Store.Read(cookie.Value)
	if err != nil {
		if errors.Is(err, ErrSessionNotFound) {
			return echo.ErrUnauthorized
		}
		return err
	}

	uri, err := redirectPath(c.Param("uri"))
	if err != nil {
		return err
	}

	if time.Now().After(current.Expired) {
		if err := s.Store.Delete(current.Token); err != nil {
			c.Logger().Info("Sessions.Refresh: Ошибка удаления сессии из SessionStore")
		}
		s.clearCookies(c)
		return echo.ErrUnauthorized
	}

	// TODO Проверить Device

	err = s.start(c, current.Claims)
	if err != nil {
		return err
	}

	if err := s.Store.Delete(current.Token); err != nil {
		c.Logger().Info("Sessions.Refresh: Ошибка удаления сессии из SessionStore")
	}

	return c.Redirect(http.StatusTemporaryRedirect, uri)
}

func redirectPath(param string) (string, error) {
	if strings.ContainsAny(param, "\\") {
		return "", echo.ErrBadRequest
	}

	u, err := url.Parse("/" + param)
	if err != nil {
		return "", echo.ErrBadRequest
	}
	if u.Scheme != "" || u.Host != "" || u.Opaque != "" || u.User != nil {
		return "", echo.ErrBadRequest
	}

	p := path.Clean(u.Path)
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") {
		return "", echo.ErrBadRequest
	}

	return p, nil
}

func (s *sessions[C]) start(c *echo.Context, claims C) error {
	claims, err := cloneAndSetExp(claims, time.Now().Add(s.AccessTimeout))
	if err != nil {
		return err
	}

	access, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.Secret)
	if err != nil {
		return err
	}

	session := Session[C]{
		Token:  uuid.NewString(),
		Claims: claims,
		Device: Device{
			IP:        c.RealIP(),
			UserAgent: c.Request().UserAgent(),
		},
		Created: time.Now(),
		Expired: time.Now().Add(s.RefreshTimeout),
	}

	if err := s.Store.Create(session); err != nil {
		return err
	}

	s.setCookies(c, access, session.Token)
	return nil
}

func (s *sessions[C]) setCookies(c *echo.Context, accessToken string, refreshToken string) {
	sessionPath := s.Prefix + "/auth"
	accessPath := s.Prefix
	if accessPath == "" {
		accessPath = "/"
	}

	c.SetCookie(&http.Cookie{
		Name:     "session",
		Value:    refreshToken,
		MaxAge:   int(s.RefreshTimeout.Seconds()),
		Expires:  time.Now().Add(s.RefreshTimeout),
		Path:     sessionPath,
		HttpOnly: true,
		Secure:   s.Secure,
		SameSite: http.SameSiteLaxMode,
	})

	c.SetCookie(&http.Cookie{
		Name:     "access",
		Value:    accessToken,
		MaxAge:   int(s.AccessTimeout.Seconds()),
		Expires:  time.Now().Add(s.AccessTimeout),
		Path:     accessPath,
		HttpOnly: false,
		Secure:   s.Secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *sessions[C]) clearCookies(c *echo.Context) {
	sessionPath := s.Prefix + "/auth"
	accessPath := s.Prefix
	if accessPath == "" {
		accessPath = "/"
	}

	c.SetCookie(&http.Cookie{
		Name:     "session",
		Value:    "",
		MaxAge:   -1,
		Expires:  time.Now(),
		Path:     sessionPath,
		HttpOnly: true,
		Secure:   s.Secure,
		SameSite: http.SameSiteLaxMode,
	})

	c.SetCookie(&http.Cookie{
		Name:     "access",
		Value:    "",
		MaxAge:   -1,
		Expires:  time.Now(),
		Path:     accessPath,
		HttpOnly: false,
		Secure:   s.Secure,
		SameSite: http.SameSiteLaxMode,
	})
}
