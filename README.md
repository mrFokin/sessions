# Sessions

Библиотека для управления сессиями пользователей в веб-приложениях на Go с использованием Echo framework. Поддерживает JWT токены, refresh tokens и различные хранилища сессий.

## Возможности

- 🔐 **JWT аутентификация** - использование access токенов на основе JWT
- 🔄 **Refresh токены** - автоматическое обновление сессий
- 🍪 **Cookie-based хранение** - безопасное хранение токенов в cookies
- 💾 **Множественные хранилища** - поддержка in-memory и Redis хранилищ
- 🛡️ **Безопасность** - HttpOnly cookies, Secure флаги, SameSite защита
- 📱 **Отслеживание устройств** - сохранение информации об IP и User-Agent
- ↩️ **Автоматический редирект** - middleware с автоматическим перенаправлением на страницу авторизации

## Установка

```bash
go get github.com/mrFokin/sessions
```

## Зависимости

- `github.com/labstack/echo/v4` - веб-фреймворк
- `github.com/golang-jwt/jwt/v5` - работа с JWT
- `github.com/google/uuid` - генерация уникальных идентификаторов
- `github.com/redis/go-redis/v9` - клиент Redis (опционально)

## Быстрый старт

### Базовая настройка с in-memory хранилищем

```go
package main

import (
    "time"
    "github.com/labstack/echo/v4"
    "github.com/golang-jwt/jwt/v5"
    "github.com/mrFokin/sessions"
    "github.com/mrFokin/sessions/store"
)

func main() {
    e := echo.New()
    
    // Создаем хранилище сессий
    sessionStore := store.NewMemoryStore()
    
    // Инициализируем менеджер сессий
    sessionManager := sessions.New(
        []byte("your-secret-key"),  // секретный ключ для JWT
        15*time.Minute,              // время жизни access токена
        24*time.Hour,                // время жизни refresh токена
        false,                       // secure (true для HTTPS)
        sessionStore,
    )
    
    // Роут для начала сессии
    e.POST("/auth/login", func(c echo.Context) error {
        // Ваша логика проверки логина/пароля
        claims := jwt.MapClaims{
            "user_id": "123",
            "email": "user@example.com",
        }
        
        if err := sessionManager.Start(c, claims); err != nil {
            return err
        }
        
        return c.JSON(200, map[string]string{"status": "ok"})
    })
    
    // Роут для обновления сессии
    e.POST("/auth/refresh/*uri", sessionManager.Refresh)
    
    // Роут для выхода
    e.POST("/auth/logout", func(c echo.Context) error {
        return sessionManager.Stop(c)
    })
    
    // Защищенный роут
    protected := e.Group("/api")
    protected.Use(sessions.JWTWithRedirect("/auth/refresh", []byte("your-secret-key"), jwt.MapClaims{}))
    protected.GET("/profile", func(c echo.Context) error {
        user := c.Get("user").(*jwt.Token)
        claims := user.Claims.(jwt.MapClaims)
        return c.JSON(200, claims)
    })
    
    e.Start(":8080")
}
```

### Использование Redis хранилища

```go
import (
    "github.com/redis/go-redis/v9"
    "github.com/mrFokin/sessions/store"
)

// Создаем Redis хранилище
redisStore := store.NewRedisStore(&redis.Options{
    Addr:     "localhost:6379",
    Password: "",
    DB:       0,
})

sessionManager := sessions.New(
    []byte("your-secret-key"),
    15*time.Minute,
    24*time.Hour,
    false,
    redisStore,
)
```

## Ограничения

Библиотека рассчитана на JSON-RPC по HTTP с cookies, а не на REST с query/fragment.

- Метод RPC в теле запроса. URL — endpoint. После refresh в `Location` попадает только same-origin path из `*uri` (`url.Parse`, без host и `//`). Иначе 400, сессия не ротируется. Query, fragment и trailing slash не восстанавливаются.
- `JWTWithRedirect` отвечает **307**. Клиент должен следовать редиректу, сохранить метод и тело, слать cookies (`credentials`). Транспорт без cookie jar или без follow redirect автоматический refresh не получит.
- Хендлер refresh вешается как **POST** `/…/auth/refresh/*uri`. 307 с JSON-RPC POST иначе получит 405 на GET-роуте.
- Cookie `session` имеет Path `{prefix}/auth`, поэтому URL refresh должен быть под этим путём — иначе refresh-токен не уйдёт.
- TTL cookie `access` совпадает с `exp` JWT: браузер не шлёт протухший access. Триггер refresh — отсутствие cookie (`ErrJWTMissing`), не разбор истёкшего JWT.

## API документация

### Интерфейс Sessions

Основной интерфейс для управления сессиями.

#### `Start(c echo.Context, claims jwt.MapClaims) error`

Создает новую сессию для пользователя.

**Параметры:**
- `c` - контекст Echo
- `claims` - JWT claims, которые будут включены в access токен

**Поведение:**
- Если существует активная сессия, она будет удалена
- Создает новый access токен с указанными claims
- Генерирует уникальный refresh токен
- Сохраняет сессию в хранилище
- Устанавливает два cookies: `access` и `session`

**Пример:**
```go
claims := jwt.MapClaims{
    "user_id": userID,
    "role": "admin",
    "email": email,
}
err := sessionManager.Start(c, claims)
```

#### `Stop(c echo.Context) error`

Завершает текущую сессию пользователя.

**Поведение:**
- Удаляет сессию из хранилища
- Очищает cookies `access` и `session`

**Пример:**
```go
err := sessionManager.Stop(c)
```

#### `Refresh(c echo.Context) error`

Обновляет истекший access токен используя refresh токен.

**Параметры:**
- Ожидает параметр пути `*uri` — path для редиректа после обновления (хвост исходного URL)

**Поведение:**
- Проверяет наличие refresh токена в cookie `session`
- Загружает сессию из хранилища
- Нормализует `*uri` в same-origin path; иначе 400 без ротации сессии
- Проверяет срок действия refresh токена
- Создает новую сессию с теми же claims
- Делает редирект 307 на нормализованный path

**Маршрут:**
```go
e.POST("/auth/refresh/*uri", sessionManager.Refresh)
```

### Конструкторы

#### `New(prefix string, secret []byte, accessTimeout time.Duration, refreshTimeout time.Duration, secure bool, store SessionStore) Sessions`

Создает менеджер сессий.

**Параметры:**
- `prefix` - префикс пути для cookies (например, `/api` или `""` для корня)
- `secret` - секретный ключ для подписи JWT токенов
- `accessTimeout` - время жизни access токена
- `refreshTimeout` - время жизни refresh токена
- `secure` - флаг Secure для cookies (true для HTTPS)
- `store` - реализация хранилища сессий

**Поведение:**
- Cookie `session` будет иметь Path: `{prefix}/auth`
- Cookie `access` будет иметь Path: `{prefix}` (или `/` если prefix пустой)

**Примеры:**

Без префикса:
```go
sessionManager := sessions.New(
    "",                 // без префикса
    []byte("secret-key"),
    15*time.Minute,
    24*time.Hour,
    true,
    store,
)
// Cookies: session @ /auth, access @ /
```

С префиксом `/api`:
```go
sessionManager := sessions.New(
    "/api",             // префикс пути
    []byte("secret-key"),
    15*time.Minute,
    24*time.Hour,
    true,
    store,
)
// Cookies: session @ /api/auth, access @ /api
```

### Интерфейс SessionStore

Интерфейс для хранения сессий. Реализован в двух вариантах: memory и redis.

#### `Create(Session) error`

Сохраняет сессию в хранилище.

#### `Read(refreshToken string) (Session, error)`

Загружает сессию по refresh токену.

**Возвращает:**
- `Session` - данные сессии
- `error` - `ErrSessionNotFound` если сессия не найдена

#### `Delete(refreshToken string) error`

Удаляет сессию из хранилища.

### Middleware

#### `JWTWithRedirect(path string, secret []byte, claims jwt.Claims) echo.MiddlewareFunc`

Middleware для защиты роутов с автоматическим редиректом на обновление токена.

**Параметры:**
- `path` - полный путь для редиректа (включая префикс, если нужен)
- `secret` - секретный ключ для верификации JWT
- `claims` - структура claims для парсинга JWT

**Поведение:**
- Проверяет access токен из cookie
- Если токен валиден - пропускает запрос дальше
- Если токен отсутствует или невалиден - делает редирект на `{path}{текущий_URI}`

**Примеры:**

Без префикса:
```go
api := e.Group("/api")
api.Use(sessions.JWTWithRedirect(
    "/auth/refresh",      // путь для refresh
    []byte("secret-key"),
    jwt.MapClaims{},
))
// Редирект: /auth/refresh/api/profile
```

С префиксом `/api`:
```go
api := e.Group("/api")
api.Use(sessions.JWTWithRedirect(
    "/api/auth/refresh",  // полный путь с префиксом
    []byte("secret-key"),
    jwt.MapClaims{},
))
// Редирект: /api/auth/refresh/api/profile
```
```

## Структуры данных

### Session

Представляет сессию пользователя.

```go
type Session struct {
    Token   string           // Уникальный refresh токен (UUID)
    Claims  jwt.MapClaims    // JWT claims пользователя
    Device  Device           // Информация об устройстве
    Created time.Time        // Время создания сессии
    Expired time.Time        // Время истечения сессии
}
```

### Device

Информация об устройстве пользователя.

```go
type Device struct {
    IP        string  // IP адрес
    UserAgent string  // User-Agent браузера
}
```

## Cookies

Библиотека использует два типа cookies:

### Cookie `session`

- **Назначение:** хранит refresh токен
- **Path:** `{prefix}/auth` (по умолчанию `/auth`)
- **Domain:** не задаётся (host-only)
- **HttpOnly:** `true` (недоступен для JavaScript)
- **Secure:** настраивается при инициализации
- **SameSite:** `Lax`
- **Время жизни:** refreshTimeout

### Cookie `access`

- **Назначение:** хранит JWT access токен
- **Path:** `{prefix}` или `/` если prefix пустой
- **Domain:** не задаётся (host-only)
- **HttpOnly:** `false` (доступен для JavaScript)
- **Secure:** настраивается при инициализации
- **SameSite:** `Lax`
- **Время жизни:** accessTimeout

**Примечание:** При использовании префикса `/api`:
- Cookie `session` будет доступен только для путей `/api/auth/*`
- Cookie `access` будет доступен для всех путей `/api/*`

## Хранилища

### Memory Store

In-memory хранилище на основе `sync.Map`. Подходит для разработки и небольших приложений.

**Преимущества:**
- Не требует внешних зависимостей
- Быстрое
- Простое в использовании

**Недостатки:**
- Данные теряются при перезапуске
- Не подходит для кластерных развертываний
- Ограничено памятью одного процесса

**Использование:**
```go
store := store.NewMemoryStore()
```

### Redis Store

Хранилище на основе Redis. Подходит для production и кластерных развертываний.

**Преимущества:**
- Данные сохраняются при перезапуске
- Поддержка кластерных развертываний
- Автоматическое истечение сессий (TTL)
- Масштабируемость

**Недостатки:**
- Требует запущенный Redis сервер
- Дополнительная сетевая задержка

**Использование:**
```go
store := store.NewRedisStore(&redis.Options{
    Addr:     "localhost:6379",
    Password: "your-password",
    DB:       0,
})
```

**Формат ключей в Redis:**
```
session:{refresh-token-uuid}
```

## Безопасность

### Рекомендации

1. **Использование HTTPS:**
   ```go
   sessions.New(secret, accessTimeout, refreshTimeout, true, store)
   ```
   Установите `secure` в `true` для production окружения.

2. **Секретный ключ:**
   - Используйте криптографически стойкий случайный ключ
   - Минимум 32 байта
   - Храните в переменных окружения, не в коде

3. **Время жизни токенов:**
   - Access токен: 15-30 минут (короткий срок)
   - Refresh токен: 1-7 дней (длительный срок)

4. **Проверка устройств:**
   В текущей версии информация о устройстве сохраняется, но не проверяется при обновлении. 
   В будущих версиях планируется добавить проверку (см. TODO в коде).

### Защита от атак

- **CSRF:** используется SameSite=Lax для cookies
- **XSS:** refresh токен хранится в HttpOnly cookie
- **Session Fixation:** при создании новой сессии старая удаляется
- **Token Replay:** короткое время жизни access токенов

## Примеры использования

### Пользовательская структура Claims

```go
type CustomClaims struct {
    UserID   string   `json:"user_id"`
    Email    string   `json:"email"`
    Roles    []string `json:"roles"`
    jwt.RegisteredClaims
}

// В middleware
api.Use(sessions.JWTWithRedirect(
    "/auth/refresh",
    []byte("secret"),
    &CustomClaims{},
))

// В обработчике
func handler(c echo.Context) error {
    user := c.Get("user").(*jwt.Token)
    claims := user.Claims.(*CustomClaims)
    
    userID := claims.UserID
    email := claims.Email
    
    return c.JSON(200, claims)
}
```

### Логирование сессий

```go
type LoggingStore struct {
    store sessions.SessionStore
    logger *log.Logger
}

func (l *LoggingStore) Create(s sessions.Session) error {
    l.logger.Printf("Creating session: %s for device: %s", s.Token, s.Device.IP)
    return l.store.Create(s)
}

func (l *LoggingStore) Read(token string) (sessions.Session, error) {
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

## Тестирование

Проект включает comprehensive тесты для всех компонентов.

### Запуск тестов

```bash
# Все тесты
go test ./...

# С покрытием
go test -cover ./...

# Генерация отчета о покрытии
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

### Структура тестов

- `sessions_test.go` - тесты основного функционала
- `middleware_test.go` - тесты middleware
- `store/memory_test.go` - тесты memory хранилища
- `store/redis_test.go` - тесты Redis хранилища (с использованием miniredis)

## Устранение проблем

### Сессия не создается

**Проблема:** После вызова `Start()` cookies не устанавливаются.

**Решение:**
- Cookies host-only (без `Domain`) — браузер привязывает их к текущему хосту, без порта в атрибуте
- Убедитесь, что `Secure` флаг соответствует протоколу (false для HTTP, true для HTTPS)

### Бесконечный редирект

**Проблема:** Запрос постоянно редиректится на `/auth/refresh`.

**Решение:**
- Проверьте, что refresh токен существует в хранилище
- Убедитесь, что refresh токен не истек
- Проверьте path для cookie `session` — он должен быть `{prefix}/auth`
- Хендлер refresh должен быть `POST /…/auth/refresh/*uri`

### Redis ошибки подключения

**Проблема:** `connection refused` при использовании Redis.

**Решение:**
```bash
# Проверьте, что Redis запущен
redis-cli ping

# Запустите Redis если необходимо
redis-server

# Проверьте настройки подключения
redis-cli -h localhost -p 6379
```

### Access токен не читается JavaScript

**Проблема:** `document.cookie` не показывает access токен.

**Решение:**
- Cookie `access` имеет `HttpOnly: false`, поэтому должен быть доступен
- Проверьте, что вы на правильном домене и path (`/`)
- Используйте DevTools браузера для проверки cookies

## Производительность

### Рекомендации

1. **Redis Connection Pooling:** 
   Клиент go-redis автоматически управляет пулом соединений. Настройте размер пула для высоконагруженных приложений:
   
   ```go
   store := store.NewRedisStore(&redis.Options{
       Addr:         "localhost:6379",
       PoolSize:     100,
       MinIdleConns: 10,
   })
   ```

2. **Memory Store Ограничения:**
   Для большого количества сессий рассмотрите периодическую очистку истекших сессий.

3. **Оптимизация времени жизни:**
   - Балансируйте между безопасностью и удобством
   - Для критичных операций требуйте повторную аутентификацию

## Roadmap

- [ ] Проверка устройств при обновлении сессии
- [ ] Поддержка множественных сессий с одного аккаунта
- [ ] Периодическая очистка истекших сессий в Memory Store
- [ ] Поддержка дополнительных хранилищ (PostgreSQL, MongoDB)
- [ ] Rate limiting для операций с сессиями
- [ ] Webhook уведомления о событиях сессий

## Участие в разработке

Приветствуются pull requests. Для значительных изменений сначала откройте issue для обсуждения.

### Процесс разработки

1. Fork репозитория
2. Создайте feature ветку (`git checkout -b feature/AmazingFeature`)
3. Commit изменения (`git commit -m 'Add some AmazingFeature'`)
4. Push в ветку (`git push origin feature/AmazingFeature`)
5. Откройте Pull Request

### Запуск тестов перед PR

```bash
go test -v -race -coverprofile=coverage.out ./...
go vet ./...
```

## Авторы

- [@mrFokin](https://github.com/mrFokin)

## Поддержка

Если у вас есть вопросы или проблемы, пожалуйста:
- Откройте [issue](https://github.com/mrFokin/sessions/issues)
- Ознакомьтесь с существующими issues и discussions

## Лицензия

Проект распространяется под лицензией MIT.

