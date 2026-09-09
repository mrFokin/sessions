# Sessions

[![Go Reference](https://pkg.go.dev/badge/github.com/mrFokin/sessions/v2.svg)](https://pkg.go.dev/github.com/mrFokin/sessions/v2)

Cookie-based session management for Go web apps on **Echo v5**. Claims are typed with generics (`Sessions[C jwt.Claims]`). For Echo v4 use [`v1.0.0`](https://github.com/mrFokin/sessions/tree/v1).

API reference: [pkg.go.dev/github.com/mrFokin/sessions/v2](https://pkg.go.dev/github.com/mrFokin/sessions/v2)

## Features

- JWT authentication — access tokens based on JWT
- Refresh tokens — automatic session rotation
- Cookie storage — tokens kept in cookies
- Multiple stores — in-memory and Redis
- Security — HttpOnly cookies, Secure flags, SameSite
- Device tracking — IP and User-Agent are stored
- Automatic redirect — middleware that sends the client to refresh

## Install

```bash
go get github.com/mrFokin/sessions/v2
```

## Dependencies

- `github.com/labstack/echo/v5` — web framework
- `github.com/golang-jwt/jwt/v5` — JWT
- `github.com/google/uuid` — unique identifiers
- `github.com/redis/go-redis/v9` — Redis client (optional)

## Quick start

### In-memory store

```go
package main

import (
    "time"
    "github.com/labstack/echo/v5"
    "github.com/golang-jwt/jwt/v5"
    "github.com/mrFokin/sessions/v2"
    "github.com/mrFokin/sessions/v2/store"
)

func main() {
    e := echo.New()
    
    sessionStore := store.NewMemoryStore[jwt.MapClaims]()
    
    sessionManager := sessions.New(
        "",                          // prefix
        []byte("your-secret-key"),  // JWT signing secret
        15*time.Minute,              // access token TTL
        24*time.Hour,                // refresh token TTL
        false,                       // secure (true for HTTPS)
        sessionStore,
    )
    
    e.POST("/auth/login", func(c *echo.Context) error {
        // your login/password check
        claims := jwt.MapClaims{
            "user_id": "123",
            "email": "user@example.com",
        }
        
        if err := sessionManager.Start(c, claims); err != nil {
            return err
        }
        
        return c.JSON(200, map[string]string{"status": "ok"})
    })
    
    e.POST("/auth/refresh/*uri", sessionManager.Refresh)
    
    e.POST("/auth/logout", func(c *echo.Context) error {
        return sessionManager.Stop(c)
    })
    
    protected := e.Group("/api")
    protected.Use(sessions.JWTWithRedirect[jwt.MapClaims]("/auth/refresh", []byte("your-secret-key")))
    protected.GET("/profile", func(c *echo.Context) error {
        user, _ := echo.ContextGet[*jwt.Token](c, "user")
        claims := user.Claims.(jwt.MapClaims)
        return c.JSON(200, claims)
    })
    
    e.Start(":8080")
}
```

### Redis store

```go
import (
    "github.com/redis/go-redis/v9"
    "github.com/mrFokin/sessions/v2/store"
)

redisStore := store.NewRedisStore[jwt.MapClaims](&redis.Options{
    Addr:     "localhost:6379",
    Password: "",
    DB:       0,
})
defer redisStore.Close()

sessionManager := sessions.New(
    "",
    []byte("your-secret-key"),
    15*time.Minute,
    24*time.Hour,
    false,
    redisStore,
)
```

## Limitations

The library is built for JSON-RPC over HTTP with cookies, not REST with query/fragment.

- The RPC method is in the request body. The URL is the endpoint. After refresh, `Location` is only the same-origin path from `*uri` (`url.Parse`, no host and no `//`). Otherwise 400, and the session is not rotated. Query, fragment, and trailing slash are not restored.
- `JWTWithRedirect` responds **307**. The client must follow the redirect, keep method and body, and send cookies (`credentials`). A transport without a cookie jar or without follow-redirect will not get automatic refresh.
- Mount refresh as **POST** `/…/auth/refresh/*uri`. A 307 from a JSON-RPC POST would otherwise get 405 on a GET route.
- Cookie `session` has Path `{prefix}/auth`, so the refresh URL must be under that path — otherwise the refresh token is not sent.
- Cookie `access` TTL matches JWT `exp`: the browser does not send an expired access cookie. Refresh is triggered by a missing cookie (`ErrJWTMissing`), not by parsing an expired JWT.

## API

### Sessions interface

The main interface for session management.

#### `Start(c *echo.Context, claims C) error`

Creates a new session for the user.

**Parameters:**
- `c` — Echo context
- `claims` — JWT claims of type `C` included in the access token

**Behavior:**
- Deletes an existing session if one is present
- Creates a new access token with the given claims
- Generates a unique refresh token
- Stores the session
- Sets two cookies: `access` and `session`

**Example:**
```go
claims := jwt.MapClaims{
    "user_id": userID,
    "role": "admin",
    "email": email,
}
err := sessionManager.Start(c, claims)
```

#### `Stop(c *echo.Context) error`

Ends the current user session.

**Behavior:**
- Deletes the session from the store
- Clears cookies `access` and `session`

**Example:**
```go
err := sessionManager.Stop(c)
```

#### `Refresh(c *echo.Context) error`

Rotates the expired access token using the refresh token.

**Parameters:**
- Expects path parameter `*uri` — the path to redirect to after refresh (tail of the original URL)

**Behavior:**
- Requires a refresh token in cookie `session`
- Loads the session from the store; `ErrSessionNotFound` → 401
- Normalizes `*uri` to a same-origin path; otherwise 400 without rotating the session
- Checks refresh token expiry
- Creates a new session with a copy of claims, then deletes the old one
- Redirects 307 to the normalized path

**Route:**
```go
e.POST("/auth/refresh/*uri", sessionManager.Refresh)
```

### Constructors

#### `New[C jwt.Claims](prefix string, secret []byte, accessTimeout time.Duration, refreshTimeout time.Duration, secure bool, store SessionStore[C]) Sessions[C]`

Creates a session manager.

**Parameters:**
- `prefix` — cookie path prefix (for example `/api` or `""` for the root). A non-empty prefix without `/` is normalized (`api` → `/api`); a trailing `/` is stripped.
- `secret` — JWT signing key
- `accessTimeout` — access token lifetime
- `refreshTimeout` — refresh token lifetime
- `secure` — Secure flag for cookies (true for HTTPS)
- `store` — session store implementation

**Behavior:**
- Cookie `session` Path: `{prefix}/auth`
- Cookie `access` Path: `{prefix}` (or `/` if prefix is empty)

**Examples:**

No prefix:
```go
sessionManager := sessions.New(
    "",                 // no prefix
    []byte("secret-key"),
    15*time.Minute,
    24*time.Hour,
    true,
    store,
)
// Cookies: session @ /auth, access @ /
```

Prefix `/api`:
```go
sessionManager := sessions.New(
    "/api",             // path prefix
    []byte("secret-key"),
    15*time.Minute,
    24*time.Hour,
    true,
    store,
)
// Cookies: session @ /api/auth, access @ /api
```

### SessionStore interface

Interface for storing sessions. Implemented as memory and redis.

#### `Create(Session[C]) error`

Stores a session.

#### `Read(refreshToken string) (Session[C], error)`

Loads a session by refresh token.

**Returns:**
- `Session` — session data
- `error` — `ErrSessionNotFound` if the session does not exist

#### `Delete(refreshToken string) error`

Deletes a session from the store.

### Middleware

#### `JWTWithRedirect[C jwt.Claims](path string, secret []byte) echo.MiddlewareFunc`

Middleware that protects routes and redirects to token refresh.

**Parameters:**
- `path` — full redirect path (include the prefix if needed)
- `secret` — JWT verification key
- type `C` — claims; a new instance is created per request

**Behavior:**
- Checks the access token from the cookie
- If the token is valid — continues
- If the token is missing or invalid — redirects to `{path}{current URI}`

**Examples:**

No prefix:
```go
api := e.Group("/api")
api.Use(sessions.JWTWithRedirect[jwt.MapClaims](
    "/auth/refresh",      // refresh path
    []byte("secret-key"),
))
// Redirect: /auth/refresh/api/profile
```

Prefix `/api`:
```go
api := e.Group("/api")
api.Use(sessions.JWTWithRedirect[jwt.MapClaims](
    "/api/auth/refresh",  // full path with prefix
    []byte("secret-key"),
))
// Redirect: /api/auth/refresh/api/profile
```

## Data types

### Session

A user session.

```go
type Session[C jwt.Claims] struct {
    Token   string        // unique refresh token (UUID)
    Claims  C             // user JWT claims
    Device  Device        // device info
    Created time.Time     // session creation time
    Expired time.Time     // session expiry
}
```

### Device

Client device info.

```go
type Device struct {
    IP        string  // client IP (Echo RealIP)
    UserAgent string  // browser User-Agent
}
```

## Cookies

The library uses two cookies:

### Cookie `session`

- **Purpose:** refresh token
- **Path:** `{prefix}/auth` (default `/auth`)
- **Domain:** unset (host-only)
- **HttpOnly:** `true` (not available to JavaScript)
- **Secure:** configured at init
- **SameSite:** `Lax`
- **Lifetime:** refreshTimeout

### Cookie `access`

- **Purpose:** JWT access token
- **Path:** `{prefix}` or `/` if prefix is empty
- **Domain:** unset (host-only)
- **HttpOnly:** `false` (available to JavaScript)
- **Secure:** configured at init
- **SameSite:** `Lax`
- **Lifetime:** accessTimeout

**Note:** With prefix `/api`:
- Cookie `session` is sent only for `/api/auth/*`
- Cookie `access` is sent for all `/api/*`

## Stores

### Memory Store

In-memory store based on `sync.Map`. Suitable for development and small apps.

**Pros:**
- No external dependencies
- Fast
- Simple

**Cons:**
- Data is lost on restart
- Not suitable for clustered deployments
- Limited to one process memory

**Usage:**
```go
store := store.NewMemoryStore[jwt.MapClaims]()
```

### Redis Store

Redis-backed store. Suitable for production and clustered deployments.

**Pros:**
- Data survives restart
- Cluster-friendly
- Automatic session expiry (TTL)
- Scalable

**Cons:**
- Requires a running Redis server
- Extra network latency

**Usage:**
```go
redisStore := store.NewRedisStore[jwt.MapClaims](&redis.Options{
    Addr:     "localhost:6379",
    Password: "your-password",
    DB:       0,
})
defer redisStore.Close()
```

`Create` with a non-positive TTL (`Expired` in the past) returns an error; the session is not written.

**Redis key format:**
```
session:{refresh-token-uuid}
```

## Security

### Recommendations

1. **Use HTTPS:**
   ```go
   sessions.New("", secret, accessTimeout, refreshTimeout, true, store)
   ```
   Set `secure` to `true` in production.

2. **Secret key:**
   - Use a cryptographically strong random key
   - At least 32 bytes
   - Keep it in environment variables, not in code

3. **Token lifetime:**
   - Access token: 15–30 minutes (short)
   - Refresh token: 1–7 days (long)

4. **Device checks:**
   Device info is stored but not verified on refresh.
   Verification is planned (see the TODO in the code).

### Attack surface

- **CSRF:** SameSite=Lax on cookies
- **XSS:** refresh token is in an HttpOnly cookie
- **Session Fixation:** starting a new session deletes the old one
- **Token Replay:** short-lived access tokens

## Usage examples

### Custom claims

```go
type CustomClaims struct {
    UserID   string   `json:"user_id"`
    Email    string   `json:"email"`
    Roles    []string `json:"roles"`
    jwt.RegisteredClaims
}

// In middleware
api.Use(sessions.JWTWithRedirect[*CustomClaims](
    "/auth/refresh",
    []byte("secret"),
))

// In a handler
func handler(c *echo.Context) error {
    user, _ := echo.ContextGet[*jwt.Token](c, "user")
    claims := user.Claims.(*CustomClaims)
    
    userID := claims.UserID
    email := claims.Email
    
    return c.JSON(200, claims)
}
```

### Session logging

```go
type LoggingStore struct {
    store sessions.SessionStore[jwt.MapClaims]
    logger *log.Logger
}

func (l *LoggingStore) Create(s sessions.Session[jwt.MapClaims]) error {
    l.logger.Printf("Creating session: %s for device: %s", s.Token, s.Device.IP)
    return l.store.Create(s)
}

func (l *LoggingStore) Read(token string) (sessions.Session[jwt.MapClaims], error) {
    session, err := l.store.Read(token)
    if err != nil {
        l.logger.Printf("Failed to read session: %s, error: %v", token, err)
        return session, err
    }
    l.logger.Printf("Session read: %s", token)
    return session, nil
}

func (l *LoggingStore) Delete(token string) error {
    l.logger.Printf("Deleting session: %s", token)
    return l.store.Delete(token)
}
```

## Testing

The project includes tests for all components.

### Running tests

```bash
# All tests
go test ./...

# With coverage
go test -cover ./...

# Coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

### Test layout

- `sessions_test.go` — core behavior
- `middleware_test.go` — middleware
- `store/memory_test.go` — memory store
- `store/redis_test.go` — Redis store (miniredis)

## Troubleshooting

### Session is not created

**Problem:** After `Start()`, cookies are not set.

**Fix:**
- Cookies are host-only (no `Domain`) — the browser binds them to the current host, without a port in the attribute
- Make sure the `Secure` flag matches the protocol (false for HTTP, true for HTTPS)

### Infinite redirect

**Problem:** The request keeps redirecting to `/auth/refresh`.

**Fix:**
- Check that the refresh token exists in the store
- Check that the refresh token has not expired
- Check the path for cookie `session` — it must be `{prefix}/auth`
- The refresh handler must be `POST /…/auth/refresh/*uri`

### Redis connection errors

**Problem:** `connection refused` when using Redis.

**Fix:**
```bash
# Check that Redis is running
redis-cli ping

# Start Redis if needed
redis-server

# Check connection settings
redis-cli -h localhost -p 6379
```

### Access token is not visible to JavaScript

**Problem:** `document.cookie` does not show the access token.

**Fix:**
- Cookie `access` has `HttpOnly: false`, so it should be visible
- Check that you are on the correct domain and path (`/`)
- Use browser DevTools to inspect cookies

## Performance

### Recommendations

1. **Redis connection pooling:**
   go-redis manages a connection pool. Tune pool size for high-load apps:
   
   ```go
   redisStore := store.NewRedisStore[jwt.MapClaims](&redis.Options{
       Addr:         "localhost:6379",
       PoolSize:     100,
       MinIdleConns: 10,
   })
   defer redisStore.Close()
   ```

2. **Memory Store limits:**
   For a large number of sessions, consider periodic cleanup of expired sessions.

3. **TTL trade-offs:**
   - Balance security and convenience
   - Require re-authentication for sensitive operations

## Roadmap

- [ ] Device checks on session refresh
- [ ] Multiple sessions per account
- [ ] Periodic cleanup of expired sessions in Memory Store
- [ ] Additional stores (PostgreSQL, MongoDB)
- [ ] Rate limiting for session operations
- [ ] Webhooks for session events

## Contributing

Pull requests are welcome. For substantial changes, open an issue first.

### Workflow

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit (`git commit -m 'Add some AmazingFeature'`)
4. Push (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Tests before a PR

```bash
go test -v -race -coverprofile=coverage.out ./...
go vet ./...
```

## Authors

- [@mrFokin](https://github.com/mrFokin)

## Support

If you have questions or problems:
- Open an [issue](https://github.com/mrFokin/sessions/issues)
- Check existing issues and discussions

## License

MIT
