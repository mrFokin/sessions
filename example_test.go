package sessions_test

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v5"
	"github.com/mrFokin/sessions/v2"
	"github.com/mrFokin/sessions/v2/store"
)

func Example() {
	e := echo.New()
	secret := []byte("secret-key-min-32-bytes-long!!!!")
	mgr := sessions.New(
		"",
		secret,
		15*time.Minute,
		24*time.Hour,
		false,
		store.NewMemoryStore[jwt.MapClaims](),
	)

	e.POST("/auth/login", func(c *echo.Context) error {
		return mgr.Start(c, jwt.MapClaims{"user_id": "123"})
	})
	e.POST("/auth/refresh/*uri", mgr.Refresh)
	e.POST("/auth/logout", func(c *echo.Context) error {
		return mgr.Stop(c)
	})

	api := e.Group("/api")
	api.Use(sessions.JWTWithRedirect[jwt.MapClaims]("/auth/refresh", secret))
	api.GET("/profile", func(c *echo.Context) error {
		return c.JSON(200, map[string]string{"ok": "true"})
	})
}

func ExampleNew() {
	mgr := sessions.New(
		"",
		[]byte("secret-key-min-32-bytes-long!!!!"),
		15*time.Minute,
		24*time.Hour,
		true,
		store.NewMemoryStore[jwt.MapClaims](),
	)
	_ = mgr
}

func ExampleJWTWithRedirect() {
	e := echo.New()
	api := e.Group("/api")
	api.Use(sessions.JWTWithRedirect[jwt.MapClaims](
		"/auth/refresh",
		[]byte("secret-key-min-32-bytes-long!!!!"),
	))
}
