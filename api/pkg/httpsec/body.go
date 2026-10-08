package httpsec

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// MaxResponseBytes is the default cap on an upstream API response body read
// into memory (SCM, ticketing, OAuth/OIDC, LLM, importer APIs). Callers with
// a known larger payload (a feed, a file) pass their own limit.
const MaxResponseBytes int64 = 10 << 20

// ErrBodyTooLarge reports a body larger than the caller's limit. The body
// is not returned: truncated data must never be parsed as if it were whole.
var ErrBodyTooLarge = errors.New("body exceeds the size limit")

// ReadLimited reads r to EOF and returns at most limit bytes; a longer body is
// ErrBodyTooLarge. Every read of an untrusted stream (an upstream HTTP
// response, an object-store download, a feed) goes through it or an
// equivalent io.LimitReader(limit+1) check, so a hostile or broken upstream
// cannot exhaust the API's memory.
func ReadLimited(r io.Reader, limit int64) ([]byte, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("httpsec: invalid read limit %d", limit)
	}
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%w (%d bytes)", ErrBodyTooLarge, limit)
	}
	return b, nil
}

// DecodeJSON reads at most limit bytes from r (see ReadLimited) and decodes
// them into v.
func DecodeJSON(r io.Reader, limit int64, v any) error {
	b, err := ReadLimited(r, limit)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// NewLimitedReader is io.LimitReader for a stream that is parsed as it is
// read (a CSV feed, a decompressor): past limit bytes it fails with
// ErrBodyTooLarge instead of reporting a clean EOF, so a parser never
// mistakes a truncated stream for a complete one.
func NewLimitedReader(r io.Reader, limit int64) io.Reader {
	return &limitedReader{r: r, n: limit}
}

type limitedReader struct {
	r io.Reader
	n int64 // bytes still allowed
}

func (l *limitedReader) Read(p []byte) (int, error) {
	if l.n <= 0 {
		// The allowance is used up: one more byte means the stream is too large.
		var probe [1]byte
		n, err := l.r.Read(probe[:])
		if n > 0 {
			return 0, ErrBodyTooLarge
		}
		return 0, err
	}
	if int64(len(p)) > l.n {
		p = p[:l.n]
	}
	n, err := l.r.Read(p)
	l.n -= int64(n)
	return n, err
}
