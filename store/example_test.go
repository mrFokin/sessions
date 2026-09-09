package store_test

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/mrFokin/sessions/v2/store"
	"github.com/redis/go-redis/v9"
)

func ExampleNewMemoryStore() {
	s := store.NewMemoryStore[jwt.MapClaims]()
	_ = s
}

func ExampleNewRedisStore() {
	s := store.NewRedisStore[jwt.MapClaims](&redis.Options{
		Addr: "localhost:6379",
	})
	defer s.Close()
}
