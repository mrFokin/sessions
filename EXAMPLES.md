# Примеры использования Sessions

Этот файл содержит практические примеры использования библиотеки sessions в различных сценариях.

## Содержание

- [Базовое приложение](#базовое-приложение)
- [Использование с префиксами путей](#использование-с-префиксами-путей)
- [Работа с пользовательскими Claims](#работа-с-пользовательскими-claims)
- [Интеграция с базой данных](#интеграция-с-базой-данных)
- [Множественные роли пользователей](#множественные-роли-пользователей)
- [Обработка ошибок](#обработка-ошибок)
- [Использование с фронтендом](#использование-с-фронтендом)

## Базовое приложение

Полный пример простого веб-приложения с аутентификацией:

```go
package main

import (
    "net/http"
    "time"

    "github.com/golang-jwt/jwt/v5"
    "github.com/labstack/echo/v4"
    "github.com/labstack/echo/v4/middleware"
    "github.com/mrFokin/sessions"
    "github.com/mrFokin/sessions/store"
)

var (
    secret         = []byte("your-super-secret-key-min-32-bytes!!")
    sessionManager sessions.Sessions
)

type LoginRequest struct {
    Username string `json:"username"`
    Password string `json:"password"`
}

func main() {
    e := echo.New()

    // Middleware
    e.Use(middleware.Logger())
    e.Use(middleware.Recover())

    // Инициализация session manager
    sessionStore := store.NewMemoryStore()
    sessionManager = sessions.New(
        "",             // без префикса
        secret,
        15*time.Minute, // access token
        7*24*time.Hour, // refresh token
        false,          // secure (для разработки)
        sessionStore,
    )

    // Публичные роуты
    e.POST("/auth/login", login)
    e.POST("/auth/logout", logout)
    e.POST("/auth/refresh/*uri", sessionManager.Refresh)

    // Защищенные роуты
    api := e.Group("/api")
    api.Use(sessions.JWTWithRedirect("/auth/refresh", secret, jwt.MapClaims{}))
    api.GET("/profile", getProfile)
    api.GET("/dashboard", getDashboard)

    e.Logger.Fatal(e.Start(":8080"))
}

func login(c echo.Context) error {
    var req LoginRequest
    if err := c.Bind(&req); err != nil {
        return c.JSON(http.StatusBadRequest, map[string]string{
            "error": "Invalid request",
        })
    }

    // Проверка учетных данных (замените на реальную проверку)
    if req.Username != "admin" || req.Password != "password" {
        return c.JSON(http.StatusUnauthorized, map[string]string{
            "error": "Invalid credentials",
        })
    }

    // Создание claims
    claims := jwt.MapClaims{
        "user_id":  "123",
        "username": req.Username,
        "email":    "admin@example.com",
    }

    // Начало сессии
    if err := sessionManager.Start(c, claims); err != nil {
        return c.JSON(http.StatusInternalServerError, map[string]string{
            "error": "Failed to create session",
        })
    }

    return c.JSON(http.StatusOK, map[string]string{
        "message": "Login successful",
    })
}

func logout(c echo.Context) error {
    if err := sessionManager.Stop(c); err != nil {
        return c.JSON(http.StatusInternalServerError, map[string]string{
            "error": "Failed to logout",
        })
    }

    return c.JSON(http.StatusOK, map[string]string{
        "message": "Logout successful",
    })
}

func getProfile(c echo.Context) error {
    user := c.Get("user").(*jwt.Token)
    claims := user.Claims.(jwt.MapClaims)

    return c.JSON(http.StatusOK, map[string]interface{}{
        "user_id":  claims["user_id"],
        "username": claims["username"],
        "email":    claims["email"],
    })
}

func getDashboard(c echo.Context) error {
    user := c.Get("user").(*jwt.Token)
    claims := user.Claims.(jwt.MapClaims)

    return c.JSON(http.StatusOK, map[string]interface{}{
        "message": "Welcome to dashboard",
        "user":    claims["username"],
    })
}
```

## Использование с префиксами путей

Пример приложения, работающего с префиксом пути `/api`:

```go
package main

import (
    "net/http"
    "time"

    "github.com/golang-jwt/jwt/v5"
    "github.com/labstack/echo/v4"
    "github.com/labstack/echo/v4/middleware"
    "github.com/mrFokin/sessions"
    "github.com/mrFokin/sessions/store"
)

var (
    secret         = []byte("your-super-secret-key-min-32-bytes!!")
    sessionManager sessions.Sessions
)

type LoginRequest struct {
    Username string `json:"username"`
    Password string `json:"password"`
}

func main() {
    e := echo.New()

    // Middleware
    e.Use(middleware.Logger())
    e.Use(middleware.Recover())

    // Инициализация session manager с префиксом /api
    sessionStore := store.NewMemoryStore()
    sessionManager = sessions.New(
        "/api",         // префикс пути
        secret,
        15*time.Minute, // access token
        7*24*time.Hour, // refresh token
        false,          // secure (для разработки)
        sessionStore,
    )

    // Публичные роуты с префиксом
    api := e.Group("/api")
    api.POST("/auth/login", login)
    api.POST("/auth/logout", logout)
    api.POST("/auth/refresh/*uri", sessionManager.Refresh)

    // Защищенные роуты с префиксом
    protected := api.Group("")
    protected.Use(sessions.JWTWithRedirect("/api/auth/refresh", secret, jwt.MapClaims{}))
    protected.GET("/profile", getProfile)
    protected.GET("/dashboard", getDashboard)
    protected.GET("/users", getUsers)

    e.Logger.Fatal(e.Start(":8080"))
}

func login(c echo.Context) error {
    var req LoginRequest
    if err := c.Bind(&req); err != nil {
        return c.JSON(http.StatusBadRequest, map[string]string{
            "error": "Invalid request",
        })
    }

    // Проверка учетных данных
    if req.Username != "admin" || req.Password != "password" {
        return c.JSON(http.StatusUnauthorized, map[string]string{
            "error": "Invalid credentials",
        })
    }

    // Создание claims
    claims := jwt.MapClaims{
        "user_id":  "123",
        "username": req.Username,
        "email":    "admin@example.com",
    }

    // Начало сессии
    if err := sessionManager.Start(c, claims); err != nil {
        return c.JSON(http.StatusInternalServerError, map[string]string{
            "error": "Failed to create session",
        })
    }

    return c.JSON(http.StatusOK, map[string]string{
        "message": "Login successful",
    })
}

func logout(c echo.Context) error {
    if err := sessionManager.Stop(c); err != nil {
        return c.JSON(http.StatusInternalServerError, map[string]string{
            "error": "Failed to logout",
        })
    }

    return c.JSON(http.StatusOK, map[string]string{
        "message": "Logout successful",
    })
}

func getProfile(c echo.Context) error {
    user := c.Get("user").(*jwt.Token)
    claims := user.Claims.(jwt.MapClaims)

    return c.JSON(http.StatusOK, map[string]interface{}{
        "user_id":  claims["user_id"],
        "username": claims["username"],
        "email":    claims["email"],
    })
}

func getDashboard(c echo.Context) error {
    user := c.Get("user").(*jwt.Token)
    claims := user.Claims.(jwt.MapClaims)

    return c.JSON(http.StatusOK, map[string]interface{}{
        "message": "Welcome to dashboard",
        "user":    claims["username"],
    })
}

func getUsers(c echo.Context) error {
    return c.JSON(http.StatusOK, map[string]interface{}{
        "users": []string{"user1", "user2", "user3"},
    })
}
```

**Важные моменты при работе с префиксами:**

1. **Cookies с правильными путями:**
   - Cookie `access` будет иметь Path: `/api`
   - Cookie `session` будет иметь Path: `/api/auth`

2. **URL редиректа:**
   - При отсутствии токена редирект будет на `/api/auth/refresh{текущий_URI}`
   - Например, для `/api/profile` редирект на `/api/auth/refresh/api/profile`

3. **Маршруты:**
   - Все маршруты должны начинаться с префикса `/api`
   - Login: `POST /api/auth/login`
   - Logout: `POST /api/auth/logout`
   - Refresh: `POST /api/auth/refresh/*uri`
   - Protected: `GET /api/profile`, `GET /api/dashboard`, etc.

4. **Middleware:**
   - В `JWTWithRedirect()` укажите полный путь с префиксом: `/api/auth/refresh`
   - Пользователь сам контролирует префикс в параметре `path`

## Работа с пользовательскими Claims

Использование структурированных claims вместо `jwt.MapClaims`:

```go
package main

import (
    "net/http"
    "time"

    "github.com/golang-jwt/jwt/v5"
    "github.com/labstack/echo/v4"
    "github.com/mrFokin/sessions"
    "github.com/mrFokin/sessions/store"
)

// Определяем структуру claims
type CustomClaims struct {
    UserID   string   `json:"user_id"`
    Username string   `json:"username"`
    Email    string   `json:"email"`
    Roles    []string `json:"roles"`
    jwt.RegisteredClaims
}

var sessionManager sessions.Sessions

func main() {
    e := echo.New()

    sessionStore := store.NewMemoryStore()
    sessionManager = sessions.New(
        []byte("secret-key"),
        15*time.Minute,
        24*time.Hour,
        false,
        sessionStore,
    )

    e.POST("/auth/login", loginWithCustomClaims)

    // Middleware с пользовательскими claims
    api := e.Group("/api")
    api.Use(sessions.JWTWithRedirect("/auth/refresh", []byte("secret-key"), &CustomClaims{}))
    api.GET("/admin", adminOnly)
    api.GET("/user", userProfile)

    e.Start(":8080")
}

func loginWithCustomClaims(c echo.Context) error {
    // Создаем claims с использованием нашей структуры
    claims := jwt.MapClaims{
        "user_id":  "user-123",
        "username": "john_doe",
        "email":    "john@example.com",
        "roles":    []string{"user", "admin"},
        "exp":      time.Now().Add(15 * time.Minute).Unix(),
    }

    if err := sessionManager.Start(c, claims); err != nil {
        return c.JSON(http.StatusInternalServerError, map[string]string{
            "error": "Failed to start session",
        })
    }

    return c.JSON(http.StatusOK, map[string]string{
        "message": "Login successful",
    })
}

func adminOnly(c echo.Context) error {
    user := c.Get("user").(*jwt.Token)
    claims := user.Claims.(*CustomClaims)

    // Проверка роли
    hasAdminRole := false
    for _, role := range claims.Roles {
        if role == "admin" {
            hasAdminRole = true
            break
        }
    }

    if !hasAdminRole {
        return c.JSON(http.StatusForbidden, map[string]string{
            "error": "Admin access required",
        })
    }

    return c.JSON(http.StatusOK, map[string]interface{}{
        "message": "Welcome admin",
        "user":    claims.Username,
    })
}

func userProfile(c echo.Context) error {
    user := c.Get("user").(*jwt.Token)
    claims := user.Claims.(*CustomClaims)

    return c.JSON(http.StatusOK, map[string]interface{}{
        "user_id":  claims.UserID,
        "username": claims.Username,
        "email":    claims.Email,
        "roles":    claims.Roles,
    })
}
```

## Интеграция с базой данных

Пример интеграции с PostgreSQL для хранения информации о пользователях:

```go
package main

import (
    "database/sql"
    "net/http"
    "time"

    "github.com/golang-jwt/jwt/v5"
    "github.com/labstack/echo/v4"
    _ "github.com/lib/pq"
    "github.com/mrFokin/sessions"
    "github.com/mrFokin/sessions/store"
    "golang.org/x/crypto/bcrypt"
)

type User struct {
    ID           int
    Username     string
    Email        string
    PasswordHash string
    Role         string
}

type UserService struct {
    db *sql.DB
}

func NewUserService(db *sql.DB) *UserService {
    return &UserService{db: db}
}

func (s *UserService) Authenticate(username, password string) (*User, error) {
    var user User
    err := s.db.QueryRow(`
        SELECT id, username, email, password_hash, role 
        FROM users 
        WHERE username = $1
    `, username).Scan(&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.Role)

    if err != nil {
        return nil, err
    }

    // Проверка пароля
    if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
        return nil, err
    }

    return &user, nil
}

type LoginRequest struct {
    Username string `json:"username"`
    Password string `json:"password"`
}

func main() {
    // Подключение к БД
    db, err := sql.Open("postgres", "postgres://user:password@localhost/mydb?sslmode=disable")
    if err != nil {
        panic(err)
    }
    defer db.Close()

    userService := NewUserService(db)

    e := echo.New()

    // Session manager с Redis для production
    sessionStore := store.NewMemoryStore()
    sessionManager := sessions.New(
        []byte("secret-key"),
        15*time.Minute,
        7*24*time.Hour,
        false,
        sessionStore,
    )

    e.POST("/auth/login", func(c echo.Context) error {
        var req LoginRequest
        if err := c.Bind(&req); err != nil {
            return c.JSON(http.StatusBadRequest, map[string]string{
                "error": "Invalid request",
            })
        }

        // Аутентификация через БД
        user, err := userService.Authenticate(req.Username, req.Password)
        if err != nil {
            return c.JSON(http.StatusUnauthorized, map[string]string{
                "error": "Invalid credentials",
            })
        }

        // Создание сессии с данными пользователя
        claims := jwt.MapClaims{
            "user_id":  user.ID,
            "username": user.Username,
            "email":    user.Email,
            "role":     user.Role,
        }

        if err := sessionManager.Start(c, claims); err != nil {
            return c.JSON(http.StatusInternalServerError, map[string]string{
                "error": "Failed to create session",
            })
        }

        return c.JSON(http.StatusOK, map[string]interface{}{
            "message": "Login successful",
            "user": map[string]interface{}{
                "username": user.Username,
                "email":    user.Email,
            },
        })
    })

    e.Start(":8080")
}
```

## Множественные роли пользователей

Middleware для проверки ролей:

```go
package main

import (
    "net/http"

    "github.com/golang-jwt/jwt/v5"
    "github.com/labstack/echo/v4"
    "github.com/mrFokin/sessions"
)

// Middleware для проверки наличия определенной роли
func RequireRole(roles ...string) echo.MiddlewareFunc {
    return func(next echo.HandlerFunc) echo.HandlerFunc {
        return func(c echo.Context) error {
            user := c.Get("user").(*jwt.Token)
            claims := user.Claims.(jwt.MapClaims)

            userRoles, ok := claims["roles"].([]interface{})
            if !ok {
                return c.JSON(http.StatusForbidden, map[string]string{
                    "error": "No roles found",
                })
            }

            // Проверяем наличие хотя бы одной требуемой роли
            for _, requiredRole := range roles {
                for _, userRole := range userRoles {
                    if userRole.(string) == requiredRole {
                        return next(c)
                    }
                }
            }

            return c.JSON(http.StatusForbidden, map[string]string{
                "error": "Insufficient permissions",
            })
        }
    }
}

func setupRoutes(e *echo.Echo, secret []byte) {
    // Защищенные роуты с проверкой ролей
    api := e.Group("/api")
    api.Use(sessions.JWTWithRedirect("/auth/refresh", secret, jwt.MapClaims{}))

    // Доступно только админам
    admin := api.Group("/admin")
    admin.Use(RequireRole("admin"))
    admin.GET("/users", listUsers)
    admin.DELETE("/users/:id", deleteUser)

    // Доступно админам и модераторам
    moderation := api.Group("/moderate")
    moderation.Use(RequireRole("admin", "moderator"))
    moderation.POST("/posts/:id/approve", approvePost)

    // Доступно всем авторизованным пользователям
    api.GET("/profile", getProfile)
}

func listUsers(c echo.Context) error {
    return c.JSON(http.StatusOK, map[string]string{
        "message": "List of users",
    })
}

func deleteUser(c echo.Context) error {
    userID := c.Param("id")
    return c.JSON(http.StatusOK, map[string]string{
        "message": "User deleted: " + userID,
    })
}

func approvePost(c echo.Context) error {
    postID := c.Param("id")
    return c.JSON(http.StatusOK, map[string]string{
        "message": "Post approved: " + postID,
    })
}

func getProfile(c echo.Context) error {
    user := c.Get("user").(*jwt.Token)
    claims := user.Claims.(jwt.MapClaims)
    return c.JSON(http.StatusOK, claims)
}
```

## Обработка ошибок

Централизованная обработка ошибок сессий:

```go
package main

import (
    "errors"
    "net/http"

    "github.com/labstack/echo/v4"
    "github.com/mrFokin/sessions"
)

func customErrorHandler(err error, c echo.Context) {
    code := http.StatusInternalServerError
    message := "Internal server error"

    // Проверка на конкретные ошибки
    if errors.Is(err, sessions.ErrSessionNotFound) {
        code = http.StatusUnauthorized
        message = "Session not found or expired"
    } else if he, ok := err.(*echo.HTTPError); ok {
        code = he.Code
        if msg, ok := he.Message.(string); ok {
            message = msg
        }
    }

    // Логирование ошибки
    c.Logger().Error(err)

    // Отправка JSON ответа
    if !c.Response().Committed {
        if c.Request().Method == http.MethodHead {
            c.NoContent(code)
        } else {
            c.JSON(code, map[string]interface{}{
                "error":      message,
                "code":       code,
                "path":       c.Request().URL.Path,
                "request_id": c.Response().Header().Get(echo.HeaderXRequestID),
            })
        }
    }
}

func main() {
    e := echo.New()

    // Установка кастомного обработчика ошибок
    e.HTTPErrorHandler = customErrorHandler

    // Остальная настройка приложения
    // ...
}
```

## Использование с фронтендом

Пример взаимодействия с JavaScript фронтендом:

```javascript
// login.js
async function login(username, password) {
    try {
        const response = await fetch('/auth/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ username, password }),
            credentials: 'include' // Важно для cookies
        });

        if (response.ok) {
            const data = await response.json();
            console.log('Login successful:', data);
            
            // Access токен доступен в cookies и можно прочитать
            const cookies = document.cookie.split(';');
            const accessToken = cookies.find(c => c.trim().startsWith('access='));
            console.log('Access token:', accessToken);
            
            // Переход на защищенную страницу
            window.location.href = '/dashboard';
        } else {
            console.error('Login failed');
        }
    } catch (error) {
        console.error('Error:', error);
    }
}

// api.js - работа с защищенными endpoints
async function fetchProfile() {
    try {
        const response = await fetch('/api/profile', {
            credentials: 'include' // Автоматически отправляет cookies
        });

        if (response.redirected) {
            // Произошел редирект на /auth/refresh
            // После обновления токена будет редирект обратно
            window.location.href = response.url;
            return;
        }

        if (response.ok) {
            const profile = await response.json();
            console.log('Profile:', profile);
            return profile;
        }
    } catch (error) {
        console.error('Error fetching profile:', error);
    }
}

// logout.js
async function logout() {
    try {
        const response = await fetch('/auth/logout', {
            method: 'POST',
            credentials: 'include'
        });

        if (response.ok) {
            console.log('Logout successful');
            window.location.href = '/login';
        }
    } catch (error) {
        console.error('Error:', error);
    }
}
```

---

Эти примеры покрывают основные сценарии использования библиотеки sessions. Для получения дополнительной информации обратитесь к основной документации в README.md.

