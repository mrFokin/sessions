package sessions

import (
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func newClaims[C jwt.Claims]() (C, error) {
	var zero C
	t := reflect.TypeOf(zero)
	if t == nil {
		m := jwt.MapClaims{}
		c, ok := any(m).(C)
		if !ok {
			return zero, errors.New("cannot allocate claims")
		}
		return c, nil
	}
	switch t.Kind() {
	case reflect.Map:
		return reflect.MakeMap(t).Interface().(C), nil
	case reflect.Ptr:
		return reflect.New(t.Elem()).Interface().(C), nil
	default:
		return zero, nil
	}
}

func unmarshalClaims[C jwt.Claims](data []byte) (C, error) {
	var zero C
	t := reflect.TypeOf(zero)
	if t == nil {
		m := jwt.MapClaims{}
		if err := json.Unmarshal(data, &m); err != nil {
			return zero, err
		}
		c, ok := any(m).(C)
		if !ok {
			return zero, errors.New("cannot allocate claims")
		}
		return c, nil
	}
	switch t.Kind() {
	case reflect.Ptr:
		v := reflect.New(t.Elem())
		if err := json.Unmarshal(data, v.Interface()); err != nil {
			return zero, err
		}
		return v.Interface().(C), nil
	case reflect.Map:
		ptr := reflect.New(t)
		ptr.Elem().Set(reflect.MakeMap(t))
		if err := json.Unmarshal(data, ptr.Interface()); err != nil {
			return zero, err
		}
		return ptr.Elem().Interface().(C), nil
	default:
		ptr := reflect.New(t)
		if err := json.Unmarshal(data, ptr.Interface()); err != nil {
			return zero, err
		}
		return ptr.Elem().Interface().(C), nil
	}
}

func cloneAndSetExp[C jwt.Claims](claims C, exp time.Time) (C, error) {
	var zero C
	raw, err := json.Marshal(claims)
	if err != nil {
		return zero, err
	}

	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return zero, err
	}
	if m == nil {
		m = make(map[string]any)
	}
	m["exp"] = exp.Unix()

	raw, err = json.Marshal(m)
	if err != nil {
		return zero, err
	}
	return unmarshalClaims[C](raw)
}
