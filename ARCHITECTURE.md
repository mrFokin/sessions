# Архитектура и дизайн Sessions

Документ описывает архитектурные решения, паттерны проектирования и внутреннюю структуру библиотеки sessions.

## Содержание

- [Общая архитектура](#общая-архитектура)
- [Основные компоненты](#основные-компоненты)
- [Паттерны проектирования](#паттерны-проектирования)
- [Поток данных](#поток-данных)
- [Безопасность](#безопасность)
- [Масштабируемость](#масштабируемость)
- [Решения и компромиссы](#решения-и-компромиссы)

## Общая архитектура

```
┌─────────────────────────────────────────────────────────┐
│                     Echo Framework                       │
│                   (HTTP Server)                          │
└────────────────────┬────────────────────────────────────┘
                     │
         ┌───────────┴───────────┐
         │                       │
┌────────▼────────┐    ┌────────▼────────┐
│   Middleware    │    │   Sessions API  │
│ JWTWithRedirect │    │ Start/Stop/     │
│                 │    │ Refresh         │
└────────┬────────┘    └────────┬────────┘
         │                      │
         │      ┌───────────────┘
         │      │
    ┌────▼──────▼─────┐
    │  Sessions Core  │
    │  - JWT handling │
    │  - Cookie mgmt  │
    └────────┬─────────┘
             │
    ┌────────▼─────────┐
    │  SessionStore    │
    │   (Interface)    │
    └────────┬─────────┘
             │
     ┌───────┴────────┐
     │                │
┌────▼─────┐   ┌─────▼──────┐
│  Memory  │   │   Redis    │
│  Store   │   │   Store    │
└──────────┘   └────────────┘
```

## Основные компоненты

### 1. Sessions Interface

Основной интерфейс для работы с сессиями:

```go
type Sessions interface {
    Start(c echo.Context, claims jwt.MapClaims) error
    Stop(c echo.Context) error
    Refresh(c echo.Context) error
}
```

**Назначение:**
- Абстракция над управлением сессиями
- Единая точка входа для операций с сессиями
- Упрощение тестирования через mock реализации

**Реализация:**
Структура `sessions` содержит всю необходимую конфигурацию и бизнес-логику.

### 2. SessionStore Interface

Интерфейс для хранения сессий:

```go
type SessionStore interface {
    Create(Session) error
    Read(refreshToken string) (Session, error)
    Delete(refreshToken string) error
}
```

**Назначение:**
- Абстракция над хранилищем данных
- Возможность легко менять бэкенд хранилища
- Поддержка различных стратегий персистентности

**Реализации:**
- `memoryStore` - in-memory хранилище на основе `sync.Map`
- `redisStore` - персистентное хранилище на основе Redis

### 3. Middleware

```go
func JWTWithRedirect(path string, secret []byte, claims jwt.Claims) echo.MiddlewareFunc
```

**Назначение:**
- Защита роутов от неавторизованного доступа
- Автоматическое обновление истекших токенов
- Интеграция с Echo middleware chain

**Особенности:**
- Использует `echo-jwt` библиотеку
- Кастомный error handler для редиректов
- Поддержка пользовательских claims структур

## Паттерны проектирования

### 1. Strategy Pattern (Стратегия)

Используется для выбора хранилища сессий:

```go
// Клиент выбирает стратегию хранения
var store SessionStore
if isProduction {
    store = NewRedisStore(redisOpts)
} else {
    store = NewMemoryStore()
}

sessionManager := sessions.New(secret, accessTimeout, refreshTimeout, secure, store)
```

**Преимущества:**
- Легко добавить новые хранилища
- Изоляция логики хранения от бизнес-логики
- Возможность менять стратегию в runtime

### 2. Builder Pattern (через конструктор)

Инициализация через функцию `New`:

```go
func New(secret []byte, accessTimeout time.Duration, 
         refreshTimeout time.Duration, secure bool, 
         store SessionStore) Sessions
```

**Преимущества:**
- Явная инициализация всех зависимостей
- Валидация параметров в одном месте
- Иммутабельная конфигурация после создания

### 3. Facade Pattern (Фасад)

Интерфейс `Sessions` скрывает сложность работы с JWT, cookies и хранилищем:

```go
// Пользователь видит простой API
sessionManager.Start(c, claims)

// Внутри происходит:
// 1. Создание JWT токена
// 2. Генерация refresh токена
// 3. Сохранение в хранилище
// 4. Установка cookies
```

### 4. Template Method (Шаблонный метод)

Метод `start` используется как в `Start`, так и в `Refresh`:

```go
func (s *sessions) Start(c echo.Context, claims jwt.MapClaims) error {
    // Специфичная логика для Start
    current, err := c.Cookie("session")
    if err == nil && current != nil {
        s.Store.Delete(current.Value)
    }
    
    // Общий шаблон
    return s.start(c, claims)
}

func (s *sessions) Refresh(c echo.Context) error {
    // Специфичная логика для Refresh
    // ...
    
    // Общий шаблон
    return s.start(c, current.Claims)
}
```

## Поток данных

### Аутентификация (Login)

```
1. POST /auth/login
   ↓
2. Проверка credentials
   ↓
3. sessionManager.Start(c, claims)
   ↓
4. Создание JWT access токена (exp: 15 min)
   ↓
5. Генерация UUID refresh токена
   ↓
6. Сохранение Session в Store
   {
     Token: uuid,
     Claims: {...},
     Device: {IP, UserAgent},
     Created: now,
     Expired: now + 7 days
   }
   ↓
7. Установка cookies:
   - access (HttpOnly: false, Path: /)
   - session (HttpOnly: true, Path: /auth)
   ↓
8. Response 200 OK
```

### Доступ к защищенному ресурсу

```
1. GET /api/profile
   Cookie: access=jwt_token
   ↓
2. JWTWithRedirect middleware
   ↓
3. Извлечение JWT из cookie
   ↓
4. Валидация JWT
   ├─ Valid → next handler
   └─ Invalid/Expired → Redirect to /auth/refresh/api/profile
```

### Обновление токена (Refresh)

```
1. POST /auth/refresh/api/profile
   Cookie: session=refresh_token
   ↓
2. sessionManager.Refresh(c)
   ↓
3. Чтение refresh токена из cookie
   ↓
4. Загрузка Session из Store
   ↓
5. Проверка срока действия
   ├─ Expired → Clear cookies + 401
   └─ Valid ↓
6. Удаление старой сессии из Store
   ↓
7. Создание новой сессии (s.start())
   ↓
8. Redirect 307 → /api/profile
   ↓
9. Клиент повторяет исходный POST с новым access токеном
```

## Безопасность

### Разделение токенов

**Access Token (JWT):**
- Короткое время жизни (15 минут)
- Хранится в cookie с `HttpOnly: false`
- Доступен для JavaScript (для API запросов)
- Содержит claims пользователя
- Валидируется криптографически

**Refresh Token (UUID):**
- Длинное время жизни (7 дней)
- Хранится в cookie с `HttpOnly: true`
- Недоступен для JavaScript
- Используется только для обновления access токена
- Может быть отозван через удаление из Store

### Cookie Security

```go
&http.Cookie{
    Name:     "session",
    Value:    refreshToken,
    MaxAge:   int(s.RefreshTimeout.Seconds()),
    Expires:  time.Now().Add(s.RefreshTimeout),
    Path:     "/auth",          // Ограничен только /auth
    HttpOnly: true,             // Защита от XSS
    Secure:   s.Secure,         // Только HTTPS в production
    SameSite: http.SameSiteLaxMode, // Защита от CSRF
}
```

Domain не задаётся: cookie host-only. `Host` с портом в `Domain` браузеры отбрасывают.

### Защита от атак

**XSS (Cross-Site Scripting):**
- Refresh токен в HttpOnly cookie
- Валидация всех входных данных
- JWT подписаны криптографически

**CSRF (Cross-Site Request Forgery):**
- SameSite=Lax для cookies
- Origin/Referer проверки на уровне Echo

**Session Fixation:**
- Удаление старой сессии при создании новой
- Генерация нового refresh токена при каждом обновлении

**Replay Attacks:**
- Короткое время жизни access токенов
- Одноразовое использование refresh токена (удаляется после refresh)

## Масштабируемость

### Горизонтальное масштабирование

**Проблема:** Multiple серверы должны разделять состояние сессий.

**Решение:** Redis Store
```go
// Все инстансы приложения используют общий Redis
redisStore := store.NewRedisStore(&redis.Options{
    Addr: "redis-cluster:6379",
})
```

**Преимущества:**
- Централизованное хранилище
- Автоматическое истечение через TTL
- Высокая доступность через Redis Cluster

### Производительность

**Memory Store:**
- O(1) операции через sync.Map
- Нет сетевых задержек
- Ограничено памятью одного сервера

**Redis Store:**
- O(1) операции Redis GET/SET
- Сетевая задержка ~1-2ms (локальный Redis)
- Connection pooling для эффективности
- Масштабируется горизонтально

## Решения и компромиссы

### 1. JWT в Cookie vs Header

**Решение:** Cookie
**Причины:**
- Автоматическая отправка браузером
- HttpOnly для refresh токена
- Упрощение фронтенд логики

**Компромисс:**
- Не подходит для native mobile apps (нужен отдельный API)

### 2. Redirect vs JSON Error

**Решение:** Redirect 307, когда cookie `access` нет
**Причины:**
- Клиент с cookies и follow redirect обновляет сессию прозрачно
- 307 сохраняет исходный POST JSON-RPC (метод и тело)

**Компромисс:**
- Дополнительный HTTP запрос
- Редирект рассчитан на cookie-клиент, который ходит за 307; транспорт без cookie jar / без follow redirect автоматический refresh не получит

### 3. MapClaims vs Typed Claims

**Решение:** MapClaims по умолчанию, но поддержка typed
**Причины:**
- Гибкость для разных use cases
- Простота использования
- Обратная совместимость с jwt-go

**Компромисс:**
- Отсутствие compile-time проверки типов для MapClaims

### 4. Одна сессия vs Множественные

**Решение:** Одна активная сессия на пользователя (текущая реализация)
**Причины:**
- Простота реализации
- Меньше нагрузка на хранилище
- Предсказуемое поведение

**Компромисс:**
- Logout на одном устройстве = logout везде
- Можно расширить для множественных сессий (см. EXAMPLES.md)

### 5. Device Tracking без проверки

**Решение:** Сохранение Device информации без проверки
**Причины:**
- IP и UserAgent могут легитимно меняться
- Проблемы с VPN, мобильными сетями

**Компромисс:**
- Меньше защиты от session hijacking
- TODO: Опциональная проверка в будущих версиях

---

Этот документ описывает текущую архитектуру библиотеки и может быть расширен по мере развития проекта.
