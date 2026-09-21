# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.4.1] - 2026-09-21

### Fixed

- `JWTWithRedirect` answered 500 for a malformed or wrongly signed access cookie: it returned the raw JWT parse error, which is not an `*echo.HTTPError`. It now returns 401 (`echojwt.ErrJWTInvalid`, "invalid or expired jwt") and still does not redirect to refresh

## [2.4.0] - 2026-09-21

### Added

- `sessions.WithNextParam()` option for `JWTWithRedirect`: the original request URI travels in the `next` query parameter (`/auth/refresh?next=%2Fapi%2Frpc%3Fq%3D1`), so the refresh route is a plain `POST /auth/refresh` with no wildcard and the query string of the original request survives the round trip. The option is off by default, so existing setups keep the path form (`/auth/refresh/api/rpc`)
- `Sessions.Refresh` reads `next` when present

### Fixed

- `Refresh` on a legacy `/auth/refresh/*uri` route always redirected to `/`: it read the path parameter `uri`, but Echo names any wildcard `*` (v4 and v5 alike), so the original path was lost and clients got 404 after a refresh. It now reads `*` (falling back to `uri` for hand-built contexts). Tests now run the refresh through a real router, which is how this went unnoticed before

## [2.3.0] - 2026-09-21

### Added

- `Sessions.RevokeUser(subject)` invalidates every session of a user (by the `sub` claim) created before the call, e.g. after a password change; sessions started afterwards are unaffected. Access tokens already issued live until they expire
- `sessions.UserRevoker` — optional `SessionStore` capability behind it, implemented by `MemoryStore` and `RedisStore`; `sessions.ErrRevokeUnsupported` for stores without it; `store.ErrEmptySubject`
- `RedisStore` records a revocation as `{prefix}revoked:{sub}` with a TTL of the refresh lifetime and compares it with `Session.Created` on `Read` (one extra `GET` per `Read`, no index or key scan)

### Changed

- `Sessions[C]` gained the `RevokeUser` method; custom implementations of that interface (for example test doubles) must add it

## [2.2.0] - 2026-09-21

### Added

- `store.WithKeyPrefix` option for `NewRedisStore`, so applications sharing one Redis database keep separate session namespaces (`{prefix}session:{token}`). Without it the key format is unchanged

## [2.1.0] - 2026-09-09

### Added

- Package overview, godoc on the exported API, and `Example*` functions for [pkg.go.dev](https://pkg.go.dev/github.com/mrFokin/sessions/v2)
- MIT `LICENSE` so pkg.go.dev can detect the license
- Exported `store.MemoryStore` and `store.RedisStore` (constructors previously returned unexported types)

### Changed

- README translated to English, with a pkg.go.dev badge

## [2.0.0] - 2026-09-09

Echo v5 and typed claims. For Echo v4 stay on [`v1.0.0`](https://github.com/mrFokin/sessions/tree/v1).

### Changed

- **Breaking:** module path is `github.com/mrFokin/sessions/v2`
- **Breaking:** Echo v4 → v5 (`labstack/echo/v5`, `labstack/echo-jwt/v5`); handlers take `*echo.Context`
- **Breaking:** claims are generic — `Sessions[C jwt.Claims]`, `SessionStore[C]`, `Session[C]`. Use `jwt.MapClaims` for the v1 shape
- **Breaking:** `JWTWithRedirect[C](path, secret)` — claims type is the type parameter, not a prototype value
- **Breaking:** `store.NewMemoryStore[C]()` and `store.NewRedisStore[C](*redis.Options)`

### Added

- Custom claim structs without `jwt.MapClaims`, e.g. `sessions.New[*CustomClaims](...)` and `JWTWithRedirect[*CustomClaims]`

[Unreleased]: https://github.com/mrFokin/sessions/compare/v2.4.1...HEAD
[2.4.1]: https://github.com/mrFokin/sessions/compare/v2.4.0...v2.4.1
[2.4.0]: https://github.com/mrFokin/sessions/compare/v2.3.0...v2.4.0
[2.3.0]: https://github.com/mrFokin/sessions/compare/v2.2.0...v2.3.0
[2.2.0]: https://github.com/mrFokin/sessions/compare/v2.1.0...v2.2.0
[2.1.0]: https://github.com/mrFokin/sessions/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/mrFokin/sessions/compare/v1.0.0...v2.0.0
