package evidence

import (
	"strings"
)

// FromToolProperties builds evidence from the HTTP proof a tool attached to a
// CTIS finding as properties (the nuclei sensor sends request, response,
// curl_command, extracted_results and matcher_name). matchedAt is the
// finding's location (the URL the check matched at). It returns nil when the
// properties carry no exchange.
//
// This is the pre-CTIS-1.6 path; a tool that sends evidence_items is read by
// Decode instead.
func FromToolProperties(props map[string]any, matchedAt, label string) []Item {
	if len(props) == 0 {
		return nil
	}
	rawReq := propString(props, "request")
	rawResp := propString(props, "response")
	extracted := propStrings(props, "extracted_results")
	matcher := propString(props, "matcher_name")
	var out []Item

	if rawReq != "" || rawResp != "" {
		ex := Item{Kind: KindHTTPExchange, Label: label, HTTP: &HTTP{
			Request:  ParseRawRequest(rawReq, matchedAt),
			Response: ParseRawResponse(rawResp),
		}}
		if ex.HTTP.Request == nil && matchedAt != "" {
			ex.HTTP.Request = &HTTPRequest{URL: matchedAt}
		}
		ex.Extracted = extracted
		ex.Match = matchesFor(ex.HTTP.Response, extracted, matcher)
		out = append(out, ex)
	}
	if curl := propString(props, "curl_command"); curl != "" {
		out = append(out, Item{Kind: KindCurl, Label: "Reproduction (tool)", Text: curl})
	}
	return out
}

// matchesFor marks where the extracted values sit in the response body; a
// tool that sent no offsets still gets the parts it extracted highlighted.
// With nothing to locate, the match names the matcher on the body as a whole.
func matchesFor(resp *HTTPResponse, extracted []string, matcher string) []Match {
	if resp == nil {
		return nil
	}
	var ms []Match
	for _, v := range extracted {
		if len(ms) >= MaxMatches {
			break
		}
		v = strings.TrimSpace(v)
		if len(v) < 2 {
			continue
		}
		if i := strings.Index(resp.Body, v); i >= 0 {
			s, e := i, i+len(v)
			ms = append(ms, Match{Location: locResponse, Part: partBody, Start: &s, End: &e, Matcher: matcher})
		}
	}
	if len(ms) == 0 && matcher != "" {
		ms = append(ms, Match{Location: locResponse, Part: partBody, Matcher: matcher})
	}
	return ms
}

func propString(props map[string]any, key string) string {
	s, _ := props[key].(string)
	return s
}

func propStrings(props map[string]any, key string) []string {
	switch v := props[key].(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, x := range v {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		if v != "" {
			return []string{v}
		}
	}
	return nil
}
