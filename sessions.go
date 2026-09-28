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

var (
	// ErrSessionNotFound is returned by SessionStore.Read when no session exists
	// for the given refresh token.
	ErrSessionNotFound = errors.New("session not found")

	// ErrRevokeUnsupported is returned by Sessions.RevokeUser when the
	// SessionStore does not implement UserRevoker.
	ErrRevokeUnsupported = errors.New("session store cannot revoke a user's sessions")
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
	//
	// The replaced refresh token keeps working for 30 seconds and yields the
	// session that replaced it rather than rotating again, so requests fired
	// together with the same expired access token all get the same session
	// instead of every one but the first being rejected.
	Refresh(c *echo.Context) error
	// RevokeUser invalidates every session of the user whose "sub" claim
	// (Claims.GetSubject) is subject: their refresh tokens stop working at once.
	// Access tokens already issued stay valid until they expire (accessTimeout).
	// Sessions started after the call are unaffected, and sessions without a
	// subject cannot be revoked. It returns ErrRevokeUnsupported if the store
	// does not implement UserRevoker.
	RevokeUser(subject string) error
}

// SessionStore persists sessions keyed by refresh token.
type SessionStore[C jwt.Claims] interface {
	// Create stores a session, replacing any session with the same Token
	// (Refresh relies on this to turn a rotated session into a pointer to its
	// successor). RedisStore requires a positive TTL (Session.Expired in the
	// future).
	Create(Session[C]) error
	// Read loads a session by refresh token.
	// It returns ErrSessionNotFound if the session does not exist.
	Read(refreshToken string) (Session[C], error)
	// Delete removes a session by refresh token.
	Delete(refreshToken string) error
}

// UserRevoker is an optional SessionStore capability: making every session of
// a subject (the "sub" claim) created up to now unreadable. ttl says how long
// the revocation must be remembered — the longest a session can live.
// MemoryStore and RedisStore implement it.
type UserRevoker interface {
	RevokeUser(subject string, ttl time.Duration) error
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

	// ReplacedBy is the refresh token of the session that replaced this one
	// in Refresh; empty for a live session. A replaced session is kept only
	// for the grace period (Expired is moved to its end).
	ReplacedBy string `json:",omitempty"`
}

// refreshGrace is how long a replaced refresh token still yields its
// successor. It covers requests that were already in flight with the old
// token; a request arriving later than that is treated as a stale token.
const refreshGrace = 30 * time.Second

// maxReplacedHops bounds how many ReplacedBy links Refresh follows: a token
// rotated more than once within the grace period still reaches the live
// session, while a corrupted store can't loop it forever.
const maxReplacedHops = 5

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
		refreshGrace:   refreshGrace,
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

	refreshGrace time.Duration // a field rather than the constant so tests can shorten it
}

func (s *sessions[C]) Start(c *echo.Context, claims C) error {
	current, err := c.Cookie("session")
	if err == nil && current != nil {
		if err := s.Store.Delete(current.Value); err != nil {
			c.Logger().Info("Sessions.Start: Ошибка удаления сессии из SessionStore")
		}
	}

	if _, err := s.start(c, claims); err != nil {
		s.clearCookies(c)
		return err
	}
	return nil
}

func (s *sessions[C]) RevokeUser(subject string) error {
	r, ok := s.Store.(UserRevoker)
	if !ok {
		return ErrRevokeUnsupported
	}
	return r.RevokeUser(subject, s.RefreshTimeout)
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

	uri, err := refreshTarget(c)
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

	if current.ReplacedBy != "" {
		live, err := s.successor(current)
		if err != nil {
			if errors.Is(err, ErrSessionNotFound) {
				return echo.ErrUnauthorized
			}
			return err
		}
		if err := s.issue(c, live); err != nil {
			return err
		}
		return c.Redirect(http.StatusTemporaryRedirect, uri)
	}

	// TODO Проверить Device

	next, err := s.start(c, current.Claims)
	if err != nil {
		return err
	}

	current.ReplacedBy = next.Token
	current.Expired = time.Now().Add(s.refreshGrace)
	if err := s.Store.Create(current); err != nil {
		c.Logger().Info("Sessions.Refresh: Ошибка сохранения заменённой сессии в SessionStore")
		// Without the grace record the old token must not outlive the rotation.
		if err := s.Store.Delete(current.Token); err != nil {
			c.Logger().Info("Sessions.Refresh: Ошибка удаления сессии из SessionStore")
		}
	}

	return c.Redirect(http.StatusTemporaryRedirect, uri)
}

// successor follows the ReplacedBy chain from a replaced session to the live
// session at its end. It returns ErrSessionNotFound if a link is missing,
// expired or revoked, or the chain is longer than maxReplacedHops.
func (s *sessions[C]) successor(replaced Session[C]) (Session[C], error) {
	current := replaced
	for range maxReplacedHops {
		next, err := s.Store.Read(current.ReplacedBy)
		if err != nil {
			return Session[C]{}, err
		}
		if time.Now().After(next.Expired) {
			return Session[C]{}, ErrSessionNotFound
		}
		if next.ReplacedBy == "" {
			return next, nil
		}
		current = next
	}
	return Session[C]{}, ErrSessionNotFound
}

// refreshTarget returns where to send the client after a refresh: the "next"
// query parameter (see WithNextParam) if present, otherwise the wildcard of a
// legacy /auth/refresh/*uri route. Echo names any wildcard "*" whatever the
// route calls it, so "uri" is only a fallback for hand-built contexts.
func refreshTarget(c *echo.Context) (string, error) {
	if next := c.QueryParam("next"); next != "" {
		return nextPath(next)
	}
	wildcard := c.Param("*")
	if wildcard == "" {
		wildcard = c.Param("uri")
	}
	return redirectPath(wildcard)
}

// nextPath validates the "next" parameter: a same-origin absolute path, no
// scheme, host, "//" prefix or backslash. The query string is kept, the
// fragment (never sent to the server) does not exist here.
func nextPath(next string) (string, error) {
	if strings.ContainsAny(next, "\\") || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
		return "", echo.ErrBadRequest
	}
	u, err := url.Parse(next)
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
	if u.RawQuery != "" {
		p += "?" + u.RawQuery
	}
	return p, nil
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

func (s *sessions[C]) start(c *echo.Context, claims C) (Session[C], error) {
	claims, err := cloneAndSetExp(claims, time.Now().Add(s.AccessTimeout))
	if err != nil {
		return Session[C]{}, err
	}

	access, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.Secret)
	if err != nil {
		return Session[C]{}, err
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
		return Session[C]{}, err
	}

	s.setCookies(c, access, session.Token)
	return session, nil
}

// issue sets the cookies of an existing session: its refresh token and a
// fresh access token for its claims. Nothing is written to the store.
func (s *sessions[C]) issue(c *echo.Context, session Session[C]) error {
	claims, err := cloneAndSetExp(session.Claims, time.Now().Add(s.AccessTimeout))
	if err != nil {
		return err
	}

	access, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.Secret)
	if err != nil {
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
