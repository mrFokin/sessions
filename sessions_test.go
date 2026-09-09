package sessions

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type initSessionStoreMock func(*mockSessionStore)

type mockSessionStore struct {
	mock.Mock
}

func (m *mockSessionStore) Create(session Session) error {
	args := m.Called(session)
	return args.Error(0)
}

func (m *mockSessionStore) Read(refreshToken string) (Session, error) {
	args := m.Called(refreshToken)
	return args.Get(0).(Session), args.Error(1)
}

func (m *mockSessionStore) Delete(refreshToken string) error {
	args := m.Called(refreshToken)
	return args.Error(0)
}

func TestStart(t *testing.T) {
	testCases := []struct {
		when   string
		current string
		err    error
		secure bool
		prefix string
		access *http.Cookie
		refresh *http.Cookie
		initSS initSessionStoreMock
	}{
		{
			when:    "Session.Start вернул неизвестную ошибку",
			current: "",
			err:     errors.New("Unknown error"),
			initSS: func(m *mockSessionStore) {
				m.On("Create", mock.Anything).Return(errors.New("Unknown error"))
			},
		},
		{
			when:    "Если все корректно при отладке (несекурная кука)",
			current: "session=123456",
			err:     nil,
			secure:  false,
			access:  &http.Cookie{MaxAge: 300, Secure: false, Path: "/"},
			refresh: &http.Cookie{MaxAge: 600, Secure: false, Path: "/auth"},
			initSS: func(m *mockSessionStore) {
				m.On("Delete", "123456").Return(nil)
				m.On("Create", mock.Anything).Return(nil)
			},
		},
		{
			when:    "Если все корректно в проде (секурная кука)",
			current: "session=123456",
			err:     nil,
			secure:  true,
			access:  &http.Cookie{MaxAge: 300, Secure: true, Path: "/"},
			refresh: &http.Cookie{MaxAge: 600, Secure: true, Path: "/auth"},
			initSS: func(m *mockSessionStore) {
				m.On("Delete", "123456").Return(nil)
				m.On("Create", mock.Anything).Return(nil)
			},
		},
		{
			when:    "Если все корректно с префиксом /api",
			current: "session=123456",
			err:     nil,
			secure:  true,
			prefix:  "/api",
			access:  &http.Cookie{MaxAge: 300, Secure: true, Path: "/api"},
			refresh: &http.Cookie{MaxAge: 600, Secure: true, Path: "/api/auth"},
			initSS: func(m *mockSessionStore) {
				m.On("Delete", "123456").Return(nil)
				m.On("Create", mock.Anything).Return(nil)
			},
		},
	}

	e := echo.New()

	for _, tc := range testCases {
		t.Log(tc.when)

		req := httptest.NewRequest(http.MethodPost, "/auth", nil)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		req.Header.Set(echo.HeaderCookie, tc.current)
		rec := httptest.NewRecorder()

		mSessionStore := &mockSessionStore{}
		tc.initSS(mSessionStore)

		h := New(tc.prefix, []byte("secret"), time.Minute*5, time.Minute*10, tc.secure, mSessionStore)

		c := e.NewContext(req, rec)

		claims := jwt.MapClaims{"Name": "Jhon Doe"}

		err := h.Start(c, claims)

		mSessionStore.AssertExpectations(t)

		assert.Equal(t, tc.err, err, "Некорректная ошибка обработчика")

		var ac *http.Cookie
		var rc *http.Cookie
		for _, ck := range rec.Result().Cookies() {
			if ck.Name == "access" {
				ac = ck
			}
			if ck.Name == "session" {
				rc = ck
			}
		}

		if tc.access != nil {
			if assert.NotNil(t, ac, "Отсутствует cookie с access-токеном") {
				assert.Equal(t, tc.access.MaxAge, ac.MaxAge)
				assert.Equal(t, tc.access.Secure, ac.Secure)
				assert.Equal(t, tc.access.Path, ac.Path)
				assert.Empty(t, ac.Domain)
			}
		}

		if tc.refresh != nil {
			if assert.NotNil(t, rc, "Отсутствует cookie с refresh-токеном") {
				assert.Equal(t, tc.refresh.MaxAge, rc.MaxAge)
				assert.Equal(t, tc.refresh.Secure, rc.Secure)
				assert.Equal(t, tc.refresh.Path, rc.Path)
				assert.Empty(t, rc.Domain)
			}
		}
	}
}

func TestStop(t *testing.T) {
	testCases := []struct {
		when    string
		current string
		err     error
		initSS  initSessionStoreMock
	}{
		{
			when:    "Нет cookie с сессией",
			current: "",
			err:     nil,
			initSS:  func(m *mockSessionStore) {},
		},
		{
			when:    "Если все корректно",
			current: "session=123456",
			err:     nil,
			initSS: func(m *mockSessionStore) {
				m.On("Delete", "123456").Return(nil)
			},
		},
	}

	e := echo.New()

	for _, tc := range testCases {
		t.Log(tc.when)

		req := httptest.NewRequest(http.MethodPost, "/auth", nil)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		req.Header.Set(echo.HeaderCookie, tc.current)
		rec := httptest.NewRecorder()

		mSessionStore := &mockSessionStore{}
		tc.initSS(mSessionStore)

		h := sessions{
			Prefix: "",
			Secret: []byte("secret"),
			Store:  mSessionStore,
		}

		c := e.NewContext(req, rec)

		err := h.Stop(c)

		mSessionStore.AssertExpectations(t)

		assert.Equal(t, tc.err, err, "Некорректная ошибка обработчика")

		var ac *http.Cookie
		var rc *http.Cookie
		for _, ck := range rec.Result().Cookies() {
			if ck.Name == "access" {
				ac = ck
			}
			if ck.Name == "session" {
				rc = ck
			}
		}

		if assert.NotNil(t, ac, "Отсутствует cookie с access-токеном") {
			assert.Equal(t, -1, ac.MaxAge)
			assert.Equal(t, false, ac.Secure)
		}

		if assert.NotNil(t, rc, "Отсутствует cookie с refresh-токеном") {
			assert.Equal(t, -1, rc.MaxAge)
			assert.Equal(t, false, rc.Secure)
		}
	}
}

func TestRedirectPath(t *testing.T) {
	testCases := []struct {
		param string
		want  string
		err   error
	}{
		{param: "rpc", want: "/rpc"},
		{param: "api/v2", want: "/api/v2"},
		{param: "", want: "/"},
		{param: "../x", want: "/x"},
		{param: "/rpc", err: echo.ErrBadRequest},
		{param: "/evil.com", err: echo.ErrBadRequest},
		{param: `\evil.com`, err: echo.ErrBadRequest},
		{param: "//evil.com", want: "/evil.com"},
		{param: "%2F%2Fevil.com", want: "/evil.com"},
	}

	for _, tc := range testCases {
		got, err := redirectPath(tc.param)
		assert.Equal(t, tc.err, err, "param=%q", tc.param)
		assert.Equal(t, tc.want, got, "param=%q", tc.param)
	}
}

func TestRefresh(t *testing.T) {
	testCases := []struct {
		when     string
		current  string
		uri      string
		err      error
		access   *http.Cookie
		refresh  *http.Cookie
		redirect string
		initSS   initSessionStoreMock
	}{
		{
			when:    "Нет cookie с сессией",
			current: "",
			err:     echo.ErrUnauthorized,
			initSS:  func(m *mockSessionStore) {},
		},
		{
			when:    "Если сессии нет в SessionStore",
			current: "session=123456",
			err:     echo.ErrUnauthorized,
			initSS: func(m *mockSessionStore) {
				m.On("Read", "123456").Return(Session{}, echo.ErrUnauthorized)
			},
		},
		{
			when:    "Если сессия истекла",
			current: "session=123456",
			err:     echo.ErrUnauthorized,
			access:  &http.Cookie{MaxAge: -1, Secure: true},
			refresh: &http.Cookie{MaxAge: -1, Secure: true},
			initSS: func(m *mockSessionStore) {
				s := Session{
					Token:   "123456",
					Claims:  jwt.MapClaims{"Name": "Jhon Doe"},
					Expired: time.Now().Add(-1 * time.Hour),
				}
				m.On("Read", "123456").Return(s, nil)
				m.On("Delete", "123456").Return(errors.New("Unknown error"))
			},
		},
		{
			when:    "Если текушая сессия не истекла, но SessionStore.Create вернул неизвестную ошибку",
			current: "session=123456",
			err:     errors.New("Unknown errror"),
			access:  &http.Cookie{MaxAge: -1, Secure: true},
			refresh: &http.Cookie{MaxAge: -1, Secure: true},
			initSS: func(m *mockSessionStore) {
				s := Session{
					Token:   "123456",
					Claims:  jwt.MapClaims{"Name": "Jhon Doe"},
					Expired: time.Now().Add(time.Hour),
				}
				m.On("Read", "123456").Return(s, nil)
				m.On("Delete", "123456").Return(nil)
				m.On("Create", mock.Anything).Return(errors.New("Unknown errror"))
			},
		},
		{
			when:     "Если все корректно",
			current:  "session=123456",
			uri:      "api/v2",
			err:      nil,
			access:   &http.Cookie{MaxAge: 300, Secure: true},
			refresh:  &http.Cookie{MaxAge: 600, Secure: true},
			redirect: "/api/v2",
			initSS: func(m *mockSessionStore) {
				s := Session{
					Token:   "123456",
					Claims:  jwt.MapClaims{"Name": "Jhon Doe"},
					Expired: time.Now().Add(time.Hour),
				}
				m.On("Read", "123456").Return(s, nil)
				m.On("Delete", "123456").Return(nil)
				m.On("Create", mock.Anything).Return(nil)
			},
		},
		{
			when:    "Open redirect через //host",
			current: "session=123456",
			uri:     "/evil.com",
			err:     echo.ErrBadRequest,
			initSS: func(m *mockSessionStore) {
				s := Session{
					Token:   "123456",
					Claims:  jwt.MapClaims{"Name": "Jhon Doe"},
					Expired: time.Now().Add(time.Hour),
				}
				m.On("Read", "123456").Return(s, nil)
			},
		},
	}

	e := echo.New()

	for _, tc := range testCases {
		t.Log(tc.when)

		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		req.Header.Set(echo.HeaderCookie, tc.current)
		rec := httptest.NewRecorder()

		mSessionStore := &mockSessionStore{}
		tc.initSS(mSessionStore)

		h := New("", []byte("secret"), time.Minute*5, time.Minute*10, true, mSessionStore)

		c := e.NewContext(req, rec)
		c.SetPath("/auth/refresh/*uri")
		c.SetParamNames("uri")
		c.SetParamValues(tc.uri)

		err := h.Refresh(c)

		mSessionStore.AssertExpectations(t)

		assert.Equal(t, tc.err, err, "Некорректная ошибка обработчика")

		var ac *http.Cookie
		var rc *http.Cookie
		for _, ck := range rec.Result().Cookies() {
			if ck.Name == "access" {
				ac = ck
			}
			if ck.Name == "session" {
				rc = ck
			}
		}

		if tc.access != nil {
			if assert.NotNil(t, ac, "Отсутствует cookie с access-токеном") {
				assert.Equal(t, tc.access.MaxAge, ac.MaxAge)
				assert.Equal(t, tc.access.Secure, ac.Secure)
			}
		}

		if tc.refresh != nil {
			if assert.NotNil(t, rc, "Отсутствует cookie с refresh-токеном") {
				assert.Equal(t, tc.refresh.MaxAge, rc.MaxAge)
				assert.Equal(t, tc.refresh.Secure, rc.Secure)
			}
		}

		if tc.redirect != "" {
			assert.Equal(t, http.StatusTemporaryRedirect, rec.Code, "Некорректный http-статус ответа")
			assert.Equal(t, tc.redirect, rec.Header().Get(echo.HeaderLocation), "Некорректный путь редиректа")
		}
	}
}
