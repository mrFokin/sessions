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
	"github.com/labstack/echo/v4"
)

var (
	ErrSessionNotFound = errors.New("session not found")
)

type Sessions interface {
	Start(c echo.Context, claims jwt.MapClaims) error
	Stop(c echo.Context) error
	Refresh(c echo.Context) error
}

type SessionStore interface {
	Create(Session) error
	Read(refreshToken string) (Session, error)
	Delete(refreshToken string) error
}

type Device struct {
	IP        string
	UserAgent string
}

type Session struct {
	Token   string
	Claims  jwt.MapClaims
	Device  Device
	Created time.Time
	Expired time.Time
}

func New(prefix string, secret []byte, accessTimeout time.Duration, refreshTimeout time.Duration, secure bool, store SessionStore) Sessions {
	return &sessions{
		Prefix:         prefix,
		Secret:         secret,
		AccessTimeout:  accessTimeout,
		RefreshTimeout: refreshTimeout,
		Secure:         secure,
		Store:          store,
	}
}

type sessions struct {
	Prefix         string
	Secret         []byte
	AccessTimeout  time.Duration
	RefreshTimeout time.Duration
	Secure         bool
	Store          SessionStore
}

func (s *sessions) Start(c echo.Context, claims jwt.MapClaims) error {
	current, err := c.Cookie("session")
	if err == nil && current != nil {
		if err := s.Store.Delete(current.Value); err != nil {
			c.Logger().Info("Sessions.Start: Ошибка удаления сессии из SessionStore")
		}
	}

	return s.start(c, claims)
}

func (s *sessions) Stop(c echo.Context) error {
	current, err := c.Cookie("session")
	if err != http.ErrNoCookie {
		if err := s.Store.Delete(current.Value); err != nil {
			c.Logger().Info("Sessions.Stop: Ошибка удаления сессии из SessionStore")
		}
	}

	s.clearCookies(c)
	return nil
}

func (s *sessions) Refresh(c echo.Context) error {
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

func copyClaims(claims jwt.MapClaims) jwt.MapClaims {
	out := make(jwt.MapClaims, len(claims))
	for k, v := range claims {
		out[k] = v
	}
	return out
}

func (s *sessions) start(c echo.Context, claims jwt.MapClaims) error {
	claims = copyClaims(claims)
	claims["exp"] = time.Now().Add(s.AccessTimeout).Unix()

	access, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.Secret)
	if err != nil {
		return err
	}

	session := Session{
		Token:  uuid.NewString(),
		Claims: claims,
		Device: Device{
			IP:        c.Request().RemoteAddr,
			UserAgent: c.Request().UserAgent(),
		},
		Created: time.Now(),
		Expired: time.Now().Add(s.RefreshTimeout),
	}

	if err := s.Store.Create(session); err != nil {
		s.clearCookies(c)
		return err
	}

	s.setCookies(c, access, session.Token)
	return nil
}

func (s *sessions) setCookies(c echo.Context, accessToken string, refreshToken string) {
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

func (s *sessions) clearCookies(c echo.Context) {
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
