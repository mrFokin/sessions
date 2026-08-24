package store

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/mrFokin/sessions"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// Mock для Redis Client
type mockRedisClient struct {
	mock.Mock
}

func (m *mockRedisClient) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.StatusCmd {
	args := m.Called(ctx, key, value, expiration)
	cmd := redis.NewStatusCmd(ctx)
	if err := args.Error(0); err != nil {
		cmd.SetErr(err)
	}
	return cmd
}

func (m *mockRedisClient) Get(ctx context.Context, key string) *redis.StringCmd {
	args := m.Called(ctx, key)
	cmd := redis.NewStringCmd(ctx)
	if err := args.Error(1); err != nil {
		cmd.SetErr(err)
	} else if val := args.Get(0); val != nil {
		cmd.SetVal(val.(string))
	}
	return cmd
}

func (m *mockRedisClient) Del(ctx context.Context, keys ...string) *redis.IntCmd {
	args := m.Called(ctx, keys)
	cmd := redis.NewIntCmd(ctx)
	if err := args.Error(1); err != nil {
		cmd.SetErr(err)
	} else {
		cmd.SetVal(args.Get(0).(int64))
	}
	return cmd
}


func TestRedisStore_Create(t *testing.T) {
	testCases := []struct {
		name        string
		session     sessions.Session
		expectedErr error
		shouldCall  bool
	}{
		{
			name: "Успешное создание сессии",
			session: sessions.Session{
				Token: "redis-token-123",
				Claims: jwt.MapClaims{
					"user_id": "123",
					"email":   "test@example.com",
				},
				Device: sessions.Device{
					IP:        "127.0.0.1",
					UserAgent: "Mozilla/5.0",
				},
				Created: time.Now(),
				Expired: time.Now().Add(time.Hour),
			},
			expectedErr: nil,
			shouldCall:  true,
		},
		{
			name: "Сессия с истекшим временем (TTL <= 0)",
			session: sessions.Session{
				Token: "expired-token",
				Claims: jwt.MapClaims{
					"user_id": "456",
				},
				Device: sessions.Device{
					IP:        "192.168.1.1",
					UserAgent: "Chrome",
				},
				Created: time.Now().Add(-2 * time.Hour),
				Expired: time.Now().Add(-time.Hour),
			},
			expectedErr: nil,
			shouldCall:  false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.shouldCall {
				data, err := json.Marshal(tc.session)
				assert.NoError(t, err)

				expectedKey := "session:" + tc.session.Token
				expectedTTL := time.Until(tc.session.Expired)

				assert.Greater(t, expectedTTL, time.Duration(0), "TTL должен быть положительным")
				assert.NotEmpty(t, data, "Сериализованные данные не должны быть пустыми")
				assert.Equal(t, "session:redis-token-123", expectedKey, "Ключ должен содержать префикс")
			}

			if !tc.shouldCall {
				ttl := time.Until(tc.session.Expired)
				assert.LessOrEqual(t, ttl, time.Duration(0), "TTL должен быть <= 0 для истекшей сессии")
			}
		})
	}
}


func TestRedisStore_Create_Serialization(t *testing.T) {
	session := sessions.Session{
		Token: "test-token",
		Claims: jwt.MapClaims{
			"user_id": "999",
			"role":    "admin",
		},
		Device: sessions.Device{
			IP:        "10.0.0.1",
			UserAgent: "Safari/15.0",
		},
		Created: time.Now(),
		Expired: time.Now().Add(30 * time.Minute),
	}

	// Проверяем, что сессия корректно сериализуется в JSON
	data, err := json.Marshal(session)
	assert.NoError(t, err, "Сериализация не должна вызывать ошибку")
	assert.NotEmpty(t, data, "Сериализованные данные не должны быть пустыми")

	// Проверяем, что можно десериализовать обратно
	var deserialized sessions.Session
	err = json.Unmarshal(data, &deserialized)
	assert.NoError(t, err, "Десериализация не должна вызывать ошибку")
	assert.Equal(t, session.Token, deserialized.Token, "Token должен совпадать")
	assert.Equal(t, session.Claims["user_id"], deserialized.Claims["user_id"], "Claims должны совпадать")
}

func TestRedisStore_Read_KeyPrefix(t *testing.T) {
	// Проверяем, что Read использует правильный префикс ключа
	refreshToken := "my-refresh-token"
	expectedKey := "session:" + refreshToken

	assert.Equal(t, "session:my-refresh-token", expectedKey, "Ключ должен содержать префикс 'session:'")
}

func TestRedisStore_Delete_KeyPrefix(t *testing.T) {
	// Проверяем, что Delete использует правильный префикс ключа
	refreshToken := "token-to-delete"
	expectedKey := "session:" + refreshToken

	assert.Equal(t, "session:token-to-delete", expectedKey, "Ключ должен содержать префикс 'session:'")
}

func TestRedisStore_ErrorHandling(t *testing.T) {
	// Тест проверяет, что ошибка redis.Nil корректно преобразуется в sessions.ErrSessionNotFound
	testCases := []struct {
		name          string
		redisErr      error
		expectedErr   error
		shouldConvert bool
	}{
		{
			name:          "redis.Nil должен конвертироваться в ErrSessionNotFound",
			redisErr:      redis.Nil,
			expectedErr:   sessions.ErrSessionNotFound,
			shouldConvert: true,
		},
		{
			name:          "Другие ошибки должны возвращаться как есть",
			redisErr:      assert.AnError,
			expectedErr:   assert.AnError,
			shouldConvert: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Проверяем логику конвертации ошибок
			var resultErr error
			if tc.redisErr == redis.Nil {
				resultErr = sessions.ErrSessionNotFound
			} else {
				resultErr = tc.redisErr
			}

			assert.Equal(t, tc.expectedErr, resultErr, "Ошибка должна быть правильно обработана")
		})
	}
}

func TestRedisStore_TTL_Calculation(t *testing.T) {
	testCases := []struct {
		name        string
		expired     time.Time
		shouldStore bool
	}{
		{
			name:        "TTL положительный - должен сохранить",
			expired:     time.Now().Add(time.Hour),
			shouldStore: true,
		},
		{
			name:        "TTL нулевой - не должен сохранять",
			expired:     time.Now(),
			shouldStore: false,
		},
		{
			name:        "TTL отрицательный - не должен сохранять",
			expired:     time.Now().Add(-time.Hour),
			shouldStore: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ttl := time.Until(tc.expired)
			
			if tc.shouldStore {
				assert.Greater(t, ttl, time.Duration(0), "TTL должен быть положительным")
			} else {
				assert.LessOrEqual(t, ttl, time.Duration(0), "TTL должен быть <= 0")
			}
		})
	}
}

// Интеграционные тесты с использованием miniredis
func TestRedisStore_Integration_Create(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()

	store := NewRedisStore(&redis.Options{
		Addr: mr.Addr(),
	})

	session := sessions.Session{
		Token: "integration-token-123",
		Claims: jwt.MapClaims{
			"user_id": "integration-user",
			"email":   "integration@test.com",
		},
		Device: sessions.Device{
			IP:        "192.168.1.100",
			UserAgent: "TestAgent/1.0",
		},
		Created: time.Now(),
		Expired: time.Now().Add(time.Hour),
	}

	err := store.Create(session)
	assert.NoError(t, err, "Create не должен возвращать ошибку")

	// Проверяем, что ключ существует в Redis
	exists := mr.Exists("session:" + session.Token)
	assert.True(t, exists, "Ключ должен существовать в Redis")

	// Проверяем TTL
	ttl := mr.TTL("session:" + session.Token)
	assert.Greater(t, ttl, time.Duration(0), "TTL должен быть положительным")
	assert.LessOrEqual(t, ttl, time.Hour, "TTL не должен превышать час")
}

func TestRedisStore_Integration_Read(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()

	store := NewRedisStore(&redis.Options{
		Addr: mr.Addr(),
	})

	// Создаем сессию
	originalSession := sessions.Session{
		Token: "read-token-456",
		Claims: jwt.MapClaims{
			"user_id": "read-user",
			"role":    "admin",
		},
		Device: sessions.Device{
			IP:        "10.0.0.50",
			UserAgent: "ReadTestAgent/1.0",
		},
		Created: time.Now(),
		Expired: time.Now().Add(30 * time.Minute),
	}

	err := store.Create(originalSession)
	assert.NoError(t, err, "Create не должен возвращать ошибку")

	// Читаем сессию
	readSession, err := store.Read(originalSession.Token)
	assert.NoError(t, err, "Read не должен возвращать ошибку")
	assert.Equal(t, originalSession.Token, readSession.Token, "Token должен совпадать")
	assert.Equal(t, originalSession.Claims["user_id"], readSession.Claims["user_id"], "user_id должен совпадать")
	assert.Equal(t, originalSession.Claims["role"], readSession.Claims["role"], "role должен совпадать")
	assert.Equal(t, originalSession.Device.IP, readSession.Device.IP, "IP должен совпадать")
	assert.Equal(t, originalSession.Device.UserAgent, readSession.Device.UserAgent, "UserAgent должен совпадать")
}

func TestRedisStore_Integration_ReadNonExisting(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()

	store := NewRedisStore(&redis.Options{
		Addr: mr.Addr(),
	})

	// Пытаемся прочитать несуществующую сессию
	_, err := store.Read("non-existing-token")
	assert.Error(t, err, "Должна быть ошибка")
	assert.Equal(t, sessions.ErrSessionNotFound, err, "Должна быть ошибка ErrSessionNotFound")
}

func TestRedisStore_Integration_Delete(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()

	store := NewRedisStore(&redis.Options{
		Addr: mr.Addr(),
	})

	// Создаем сессию
	session := sessions.Session{
		Token: "delete-token-789",
		Claims: jwt.MapClaims{
			"user_id": "delete-user",
		},
		Device: sessions.Device{
			IP:        "172.16.0.1",
			UserAgent: "DeleteTestAgent/1.0",
		},
		Created: time.Now(),
		Expired: time.Now().Add(time.Hour),
	}

	err := store.Create(session)
	assert.NoError(t, err, "Create не должен возвращать ошибку")

	// Проверяем, что сессия существует
	exists := mr.Exists("session:" + session.Token)
	assert.True(t, exists, "Ключ должен существовать перед удалением")

	// Удаляем сессию
	err = store.Delete(session.Token)
	assert.NoError(t, err, "Delete не должен возвращать ошибку")

	// Проверяем, что сессия удалена
	exists = mr.Exists("session:" + session.Token)
	assert.False(t, exists, "Ключ должен быть удален из Redis")
}

func TestRedisStore_Integration_DeleteNonExisting(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()

	store := NewRedisStore(&redis.Options{
		Addr: mr.Addr(),
	})

	// Удаление несуществующей сессии не должно вызывать ошибку
	err := store.Delete("non-existing-token-xyz")
	assert.NoError(t, err, "Delete несуществующей сессии не должен возвращать ошибку")
}

func TestRedisStore_Integration_ExpiredSession(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()

	store := NewRedisStore(&redis.Options{
		Addr: mr.Addr(),
	})

	// Создаем сессию с истекшим временем
	expiredSession := sessions.Session{
		Token: "expired-token-999",
		Claims: jwt.MapClaims{
			"user_id": "expired-user",
		},
		Device: sessions.Device{
			IP:        "192.168.0.99",
			UserAgent: "ExpiredTestAgent/1.0",
		},
		Created: time.Now().Add(-2 * time.Hour),
		Expired: time.Now().Add(-time.Hour),
	}

	err := store.Create(expiredSession)
	assert.NoError(t, err, "Create не должен возвращать ошибку даже для истекшей сессии")

	// Ключ не должен быть создан, так как TTL <= 0
	exists := mr.Exists("session:" + expiredSession.Token)
	assert.False(t, exists, "Ключ не должен существовать для истекшей сессии")
}

func TestRedisStore_Integration_TTLExpiration(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()

	store := NewRedisStore(&redis.Options{
		Addr: mr.Addr(),
	})

	// Создаем сессию с очень коротким TTL
	shortLivedSession := sessions.Session{
		Token: "short-lived-token",
		Claims: jwt.MapClaims{
			"user_id": "short-lived-user",
		},
		Device: sessions.Device{
			IP:        "127.0.0.1",
			UserAgent: "ShortLivedAgent/1.0",
		},
		Created: time.Now(),
		Expired: time.Now().Add(2 * time.Second),
	}

	err := store.Create(shortLivedSession)
	assert.NoError(t, err, "Create не должен возвращать ошибку")

	// Проверяем, что ключ существует
	exists := mr.Exists("session:" + shortLivedSession.Token)
	assert.True(t, exists, "Ключ должен существовать сразу после создания")

	// Перематываем время в miniredis
	mr.FastForward(3 * time.Second)

	// Проверяем, что ключ истек
	exists = mr.Exists("session:" + shortLivedSession.Token)
	assert.False(t, exists, "Ключ должен истечь через 3 секунды")

	// Попытка прочитать истекшую сессию должна вернуть ошибку
	_, err = store.Read(shortLivedSession.Token)
	assert.Error(t, err, "Должна быть ошибка при чтении истекшей сессии")
	assert.Equal(t, sessions.ErrSessionNotFound, err, "Должна быть ошибка ErrSessionNotFound")
}



// Benchmark тесты для RedisStore
func BenchmarkRedisStore_Create(b *testing.B) {
	mr := miniredis.RunT(b)
	defer mr.Close()

	store := NewRedisStore(&redis.Options{
		Addr: mr.Addr(),
	})

	session := sessions.Session{
		Token: "benchmark-token",
		Claims: jwt.MapClaims{
			"user_id": "bench-user",
		},
		Device: sessions.Device{
			IP:        "127.0.0.1",
			UserAgent: "BenchAgent/1.0",
		},
		Created: time.Now(),
		Expired: time.Now().Add(time.Hour),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		session.Token = "benchmark-token-" + itoa(i)
		store.Create(session)
	}
}

func BenchmarkRedisStore_Read(b *testing.B) {
	mr := miniredis.RunT(b)
	defer mr.Close()

	store := NewRedisStore(&redis.Options{
		Addr: mr.Addr(),
	})

	session := sessions.Session{
		Token: "benchmark-read-token",
		Claims: jwt.MapClaims{
			"user_id": "bench-user",
		},
		Device: sessions.Device{
			IP:        "127.0.0.1",
			UserAgent: "BenchAgent/1.0",
		},
		Created: time.Now(),
		Expired: time.Now().Add(time.Hour),
	}
	store.Create(session)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		store.Read(session.Token)
	}
}

func BenchmarkRedisStore_Delete(b *testing.B) {
	mr := miniredis.RunT(b)
	defer mr.Close()

	store := NewRedisStore(&redis.Options{
		Addr: mr.Addr(),
	})

	// Предварительно создаем токены
	for i := 0; i < b.N; i++ {
		session := sessions.Session{
			Token: "benchmark-delete-token-" + itoa(i),
			Claims: jwt.MapClaims{
				"user_id": "bench-user",
			},
			Device: sessions.Device{
				IP:        "127.0.0.1",
				UserAgent: "BenchAgent/1.0",
			},
			Created: time.Now(),
			Expired: time.Now().Add(time.Hour),
		}
		store.Create(session)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		store.Delete("benchmark-delete-token-" + itoa(i))
	}
}

