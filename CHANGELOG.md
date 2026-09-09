# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/mrFokin/sessions/compare/v2.1.0...HEAD
[2.1.0]: https://github.com/mrFokin/sessions/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/mrFokin/sessions/compare/v1.0.0...v2.0.0
