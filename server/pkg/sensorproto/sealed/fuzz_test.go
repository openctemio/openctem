package sealed

import (
	"crypto/ed25519"
	"testing"
	"time"
)

// FuzzOpenRequest: arbitrary bytes never panic and never open.
func FuzzOpenRequest(f *testing.F) {
	k, _ := GenerateKey()
	r := Route{Realm: "r", SensorID: "s"}
	good, _ := SealRequest(k.Public(), r, &Request{RequestMeta: RequestMeta{Method: "GET", Path: "/", ReplyKey: k.Public().Bytes()}})
	f.Add(good)
	f.Add([]byte("OCSE\x01\x01\x00\x01"))
	f.Fuzz(func(t *testing.T, env []byte) {
		if _, err := OpenRequest([]*PrivateKey{k}, r, env); err == nil && string(env) != string(good) {
			t.Fatal("forged envelope opened")
		}
		_, _ = PeekHeader(env)
	})
}

// FuzzUnframe: the inner framing never panics.
func FuzzUnframe(f *testing.F) {
	pt, _ := frame(RequestMeta{ID: "1", Method: "GET", Path: "/", ReplyKey: []byte("k")}, []byte("b"))
	f.Add(pt)
	f.Add([]byte{0, 0, 0, 2, '{', '}'})
	f.Fuzz(func(t *testing.T, pt []byte) {
		var m RequestMeta
		_, _ = unframe(pt, &m)
		var rm ResponseMeta
		_, _ = unframe(pt, &rm)
	})
}

// FuzzOpenResponse: arbitrary bytes never panic and never open.
func FuzzOpenResponse(f *testing.F) {
	k, _ := GenerateKey()
	pub, _, _ := ed25519.GenerateKey(nil)
	r := Route{Realm: "r", SensorID: "s"}
	f.Add([]byte("OCSE\x01\x02\x00\x01"))
	f.Fuzz(func(t *testing.T, env []byte) {
		if _, err := OpenResponse(k, []ed25519.PublicKey{pub}, r, [32]byte{}, env, time.Now()); err == nil {
			t.Fatal("forged response opened")
		}
	})
}
