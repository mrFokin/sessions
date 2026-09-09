// Package sessions provides cookie-based session management for Echo v5.
//
// Claims are typed with generics as Sessions[C jwt.Claims]. The manager stores
// a JWT access token in the access cookie and a refresh token in the HttpOnly
// session cookie.
//
// Typical flow:
//
//	Start → JWTWithRedirect → POST /{prefix}/auth/refresh/*uri (307) → Stop
//
// Cookie paths: session is {prefix}/auth; access is {prefix} or / when prefix
// is empty. Register refresh under that session path so the refresh cookie is
// sent.
//
// The library targets JSON-RPC over HTTP with cookies, not REST with query or
// fragment. After refresh, Location is a same-origin path derived from *uri
// (no host, no "//"). JWTWithRedirect responds 307; the client must follow the
// redirect, keep method and body, and send cookies. Mount refresh as POST so a
// JSON-RPC POST does not hit 405 on a GET route.
package sessions
