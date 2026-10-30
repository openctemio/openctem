package evidence

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

// MaxManualPerFinding bounds the request/response items people record on one
// finding (a pentest write-up, an import, a drafted finding).
const MaxManualPerFinding = 50

// FromRequestResponse builds an http_exchange item from one request/response
// a person recorded on a finding. Two shapes are read:
//
//   - raw, as proxies export it: "request" and "response" hold the HTTP/1.x
//     messages as text; "url" (optional) is the URL a path-only request line
//     was sent to;
//   - structured: "method", "url", "request_headers" (an object or a list of
//     {name, value}), "request_body", "response_status", "response_headers",
//     "response_body".
//
// "notes" becomes the item's label. It returns false when the entry holds
// nothing to show. The item is not normalized or masked: the evidence
// service does both before anything is stored.
func FromRequestResponse(m map[string]any) (Item, bool) {
	if len(m) == 0 {
		return Item{}, false
	}
	it := Item{Kind: KindHTTPExchange, Label: propString(m, "notes"), HTTP: &HTTP{}}
	rawReq, rawResp := propString(m, "request"), propString(m, "response")
	base := propString(m, "url")
	if rawReq != "" || rawResp != "" {
		it.HTTP.Request = ParseRawRequest(rawReq, base)
		it.HTTP.Response = ParseRawResponse(rawResp)
		if it.HTTP.Request == nil && base != "" {
			it.HTTP.Request = &HTTPRequest{URL: base}
		}
	} else {
		method, body := propString(m, "method"), propString(m, "request_body")
		hs := headerList(m["request_headers"])
		if method != "" || base != "" || body != "" || len(hs) > 0 {
			it.HTTP.Request = &HTTPRequest{Method: strings.ToUpper(method), URL: base, Headers: hs, Body: body, BodySize: len(body)}
		}
		status, rbody := propInt(m["response_status"]), propString(m, "response_body")
		rhs := headerList(m["response_headers"])
		if status > 0 || rbody != "" || len(rhs) > 0 {
			it.HTTP.Response = &HTTPResponse{Status: status, Headers: rhs, Body: rbody, BodySize: len(rbody)}
		}
	}
	if it.HTTP.Request == nil && it.HTTP.Response == nil {
		return Item{}, false
	}
	return it, true
}

// ContainsPlaceholder reports whether any text of a request/response entry
// already holds an evidence placeholder: a masked item sent back. Storing it
// again would keep the placeholder without its value.
func ContainsPlaceholder(m map[string]any) bool {
	for _, v := range m {
		switch x := v.(type) {
		case string:
			if len(Placeholders(x)) > 0 {
				return true
			}
		case map[string]any:
			if ContainsPlaceholder(x) {
				return true
			}
		case []any:
			for _, e := range x {
				if em, ok := e.(map[string]any); ok && ContainsPlaceholder(em) {
					return true
				}
				if s, ok := e.(string); ok && len(Placeholders(s)) > 0 {
					return true
				}
			}
		}
	}
	return false
}

// headerList reads headers given as an object (sorted by name, so the same
// headers always hash the same) or as a list of {name, value}.
func headerList(v any) []Header {
	switch x := v.(type) {
	case map[string]any:
		names := make([]string, 0, len(x))
		for k := range x {
			names = append(names, k)
		}
		sort.Strings(names)
		out := make([]Header, 0, len(names))
		for _, k := range names {
			out = append(out, Header{Name: k, Value: scalarString(x[k])})
		}
		return out
	case map[string]string:
		names := make([]string, 0, len(x))
		for k := range x {
			names = append(names, k)
		}
		sort.Strings(names)
		out := make([]Header, 0, len(names))
		for _, k := range names {
			out = append(out, Header{Name: k, Value: x[k]})
		}
		return out
	case []any:
		out := make([]Header, 0, len(x))
		for _, e := range x {
			if hm, ok := e.(map[string]any); ok {
				if n := scalarString(hm["name"]); n != "" {
					out = append(out, Header{Name: n, Value: scalarString(hm["value"])})
				}
			}
		}
		return out
	}
	return nil
}

func scalarString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case nil:
		return ""
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case []any:
		parts := make([]string, 0, len(x))
		for _, e := range x {
			parts = append(parts, scalarString(e))
		}
		return strings.Join(parts, ", ")
	default:
		return fmt.Sprint(x)
	}
}

func propInt(v any) int {
	switch x := v.(type) {
	case float64:
		if x > 0 && x < math.MaxInt32 {
			return int(x)
		}
	case int:
		return x
	case string:
		if n, err := strconv.Atoi(strings.TrimSpace(x)); err == nil {
			return n
		}
	}
	return 0
}
