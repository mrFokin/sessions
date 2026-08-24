package store

import (
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/mrFokin/sessions"
	"github.com/stretchr/testify/assert"
)

func TestMemoryStore_Create(t *testing.T) {
	store := NewMemoryStore()

	session := sessions.Session{
		Token: "test-token-123",
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
	}

	err := store.Create(session)
	assert.NoError(t, err, "Create не должен возвращать ошибку")

	// Проверяем, что сессия действительно сохранена
	val, ok := store.sessions.Load(session.Token)
	assert.True(t, ok, "Сессия должна быть сохранена в store")
	assert.Equal(t, session, val.(sessions.Session), "Сохраненная сессия должна соответствовать оригиналу")
}

func TestMemoryStore_Read(t *testing.T) {
	testCases := []struct {
		name          string
		token         string
		existingToken string
		expectedErr   error
		shouldExist   bool
	}{
		{
			name:          "Чтение существующей сессии",
			token:         "existing-token",
			existingToken: "existing-token",
			expectedErr:   nil,
			shouldExist:   true,
		},
		{
			name:        "Чтение несуществующей сессии",
			token:       "non-existing-token",
			expectedErr: sessions.ErrSessionNotFound,
			shouldExist: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			store := NewMemoryStore()

			expectedSession := sessions.Session{
				Token: tc.existingToken,
				Claims: jwt.MapClaims{
					"user_id": "456",
				},
				Device: sessions.Device{
					IP:        "192.168.1.1",
					UserAgent: "Chrome",
				},
				Created: time.Now(),
				Expired: time.Now().Add(2 * time.Hour),
			}

			if tc.existingToken != "" {
				store.sessions.Store(tc.existingToken, expectedSession)
			}

			session, err := store.Read(tc.token)

			if tc.expectedErr != nil {
				assert.Error(t, err, "Ожидалась ошибка")
				assert.Equal(t, tc.expectedErr, err, "Тип ошибки должен совпадать")
			} else {
				assert.NoError(t, err, "Не должно быть ошибки")
				assert.Equal(t, expectedSession, session, "Прочитанная сессия должна соответствовать сохраненной")
			}
		})
	}
}

func TestMemoryStore_Delete(t *testing.T) {
	store := NewMemoryStore()

	token := "token-to-delete"
	session := sessions.Session{
		Token: token,
		Claims: jwt.MapClaims{
			"user_id": "789",
		},
		Device: sessions.Device{
			IP:        "10.0.0.1",
			UserAgent: "Safari",
		},
		Created: time.Now(),
		Expired: time.Now().Add(time.Hour),
	}

	// Сначала создаем сессию
	store.sessions.Store(token, session)

	// Проверяем, что сессия существует
	_, ok := store.sessions.Load(token)
	assert.True(t, ok, "Сессия должна существовать перед удалением")

	// Удаляем сессию
	err := store.Delete(token)
	assert.NoError(t, err, "Delete не должен возвращать ошибку")

	// Проверяем, что сессия удалена
	_, ok = store.sessions.Load(token)
	assert.False(t, ok, "Сессия должна быть удалена")
}

func TestMemoryStore_DeleteNonExisting(t *testing.T) {
	store := NewMemoryStore()

	// Удаление несуществующей сессии не должно вызывать ошибку
	err := store.Delete("non-existing-token")
	assert.NoError(t, err, "Delete несуществующей сессии не должен возвращать ошибку")
}

func TestMemoryStore_ConcurrentAccess(t *testing.T) {
	store := NewMemoryStore()
	
	const goroutines = 100
	const iterations = 10

	var wg sync.WaitGroup
	wg.Add(goroutines * 3) // Create, Read, Delete

	// Параллельное создание сессий
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				token := generateToken(id, j)
				session := sessions.Session{
					Token: token,
					Claims: jwt.MapClaims{
						"user_id": id,
						"iter":    j,
					},
					Device: sessions.Device{
						IP:        "127.0.0.1",
						UserAgent: "Test",
					},
					Created: time.Now(),
					Expired: time.Now().Add(time.Hour),
				}
				err := store.Create(session)
				assert.NoError(t, err)
			}
		}(i)
	}

	// Параллельное чтение сессий
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				token := generateToken(id, j)
				// Даем время на создание
				time.Sleep(time.Millisecond)
				_, _ = store.Read(token)
			}
		}(i)
	}

	// Параллельное удаление сессий
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				token := generateToken(id, j)
				// Даем время на создание
				time.Sleep(2 * time.Millisecond)
				err := store.Delete(token)
				assert.NoError(t, err)
			}
		}(i)
	}

	wg.Wait()

	// Проверяем, что store не упал и работает
	testSession := sessions.Session{
		Token:   "final-test-token",
		Claims:  jwt.MapClaims{"test": "final"},
		Device:  sessions.Device{IP: "127.0.0.1", UserAgent: "Final"},
		Created: time.Now(),
		Expired: time.Now().Add(time.Hour),
	}
	err := store.Create(testSession)
	assert.NoError(t, err, "Store должен корректно работать после конкурентного доступа")

	readSession, err := store.Read("final-test-token")
	assert.NoError(t, err)
	assert.Equal(t, testSession, readSession)
}

// Вспомогательная функция для генерации уникальных токенов
func generateToken(id, iter int) string {
	// Простая конкатенация без использования fmt для избежания импорта
	return "token-" + itoa(id) + "-" + itoa(iter)
}

// Простая функция преобразования int в string
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	
	neg := n < 0
	if neg {
		n = -n
	}
	
	buf := make([]byte, 0, 10)
	for n > 0 {
		buf = append(buf, byte('0'+n%10))
		n /= 10
	}
	
	if neg {
		buf = append(buf, '-')
	}
	
	// Разворачиваем
	for i, j := 0, len(buf)-1; i < j; i, j = i+1, j-1 {
		buf[i], buf[j] = buf[j], buf[i]
	}
	
	return string(buf)
}

// Benchmark тесты для MemoryStore
func BenchmarkMemoryStore_Create(b *testing.B) {
	store := NewMemoryStore()
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

func BenchmarkMemoryStore_Read(b *testing.B) {
	store := NewMemoryStore()
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

func BenchmarkMemoryStore_Delete(b *testing.B) {
	store := NewMemoryStore()
	
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

func BenchmarkMemoryStore_ConcurrentRead(b *testing.B) {
	store := NewMemoryStore()
	session := sessions.Session{
		Token: "concurrent-read-token",
		Claims: jwt.MapClaims{
			"user_id": "concurrent-user",
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
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			store.Read(session.Token)
		}
	})
}
