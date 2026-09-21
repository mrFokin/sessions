package store

import "github.com/golang-jwt/jwt/v5"

// subjectOf returns the "sub" claim, or "" if there is none. A nil claims
// value (possible for pointer claim types) counts as no subject instead of
// panicking.
func subjectOf[C jwt.Claims](claims C) (sub string) {
	defer func() {
		if recover() != nil {
			sub = ""
		}
	}()
	sub, _ = claims.GetSubject()
	return sub
}
