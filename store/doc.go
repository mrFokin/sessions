// Package store provides SessionStore implementations for the sessions package.
//
// MemoryStore keeps sessions in process memory. RedisStore persists sessions in
// Redis with a TTL derived from Session.Expired. Keys are {prefix}session:{token};
// the prefix is empty unless WithKeyPrefix is given.
package store
