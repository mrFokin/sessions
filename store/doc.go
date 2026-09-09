// Package store provides SessionStore implementations for the sessions package.
//
// MemoryStore keeps sessions in process memory. RedisStore persists sessions in
// Redis with a TTL derived from Session.Expired. Keys are session:{token}.
package store
