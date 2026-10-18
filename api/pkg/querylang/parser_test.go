package querylang

import (
	"reflect"
	"strings"
	"testing"
)

// stripSpans returns a copy of q with every span zeroed, for comparing
// trees parsed from different texts.
func stripSpans(q *Query) *Query {
	if q == nil {
		return nil
	}
	cp := &Query{Entity: q.Entity, Where: stripExpr(q.Where)}
	for _, st := range q.Pipeline {
		s := Stage{Kind: st.Kind, Field: Path{Name: st.Field.Name}, Interval: st.Interval, N: st.N}
		for _, p := range st.By {
			s.By = append(s.By, Path{Name: p.Name})
		}
		for _, a := range st.Aggs {
			s.Aggs = append(s.Aggs, Agg{Func: a.Func, Field: Path{Name: a.Field.Name}, As: a.As})
		}
		for _, k := range st.Keys {
			s.Keys = append(s.Keys, SortKey{Name: Path{Name: k.Name.Name}, Desc: k.Desc})
		}
		cp.Pipeline = append(cp.Pipeline, s)
	}
	return cp
}

func stripValue(v Value) Value { return Value{Kind: v.Kind, Text: v.Text} }

func stripExpr(e Expr) Expr {
	switch x := e.(type) {
	case nil:
		return nil
	case *Logic:
		out := &Logic{Kind: x.Kind}
		for _, t := range x.Terms {
			out.Terms = append(out.Terms, stripExpr(t))
		}
		return out
	case *Not:
		return &Not{X: stripExpr(x.X)}
	case *Compare:
		return &Compare{Path: Path{Name: x.Path.Name}, Op: x.Op, Value: stripValue(x.Value)}
	case *In:
		out := &In{Path: Path{Name: x.Path.Name}, Negate: x.Negate}
		for _, v := range x.Values {
			out.Values = append(out.Values, stripValue(v))
		}
		return out
	case *Between:
		return &Between{Path: Path{Name: x.Path.Name}, Lo: stripValue(x.Lo), Hi: stripValue(x.Hi)}
	case *IsEmpty:
		return &IsEmpty{Path: Path{Name: x.Path.Name}, Negate: x.Negate}
	case *Text:
		return &Text{Value: stripValue(x.Value)}
	}
	panic("unknown expr")
}

func TestParseCanonical(t *testing.T) {
	cases := []struct{ in, want string }{
		{"findings", "findings"},
		{"where severity = critical", "findings where severity = critical"},
		{"FINDINGS WHERE Severity = critical AND state=open", "findings where severity = critical and state = open"},
		{"findings where a = 1 or (b = 2 or c = 3)", "findings where a = 1 or b = 2 or c = 3"},
		{"findings where (a = 1 or b = 2) and c = 3", "findings where (a = 1 or b = 2) and c = 3"},
		{"findings where a = 1 or b = 2 and c = 3", "findings where a = 1 or b = 2 and c = 3"},
		{"findings where not not a = 1", "findings where not not a = 1"},
		{"findings where not (a = 1 and b = 2)", "findings where not (a = 1 and b = 2)"},
		{`findings where cve_id in ("CVE-2026-1", "CVE-2026-2") and tool_name not in (nuclei)`,
			`findings where cve_id in ("CVE-2026-1", "CVE-2026-2") and tool_name not in (nuclei)`},
		{"findings where cvss_score between 7 and 9.5", "findings where cvss_score between 7 and 9.5"},
		{"findings where resolved_at is empty and assigned_to is not empty", "findings where resolved_at is empty and assigned_to is not empty"},
		{`findings where text ~ "say \"hi\" \\ there"`, `findings where text ~ "say \"hi\" \\ there"`},
		{"findings where first_detected_at < -14d and epss_score >= -0.5", "findings where first_detected_at < -14d and epss_score >= -0.5"},
		{"findings where asset.type = domain", "findings where asset.type = domain"},
		{"findings | count by severity, asset.type", "findings | count by severity, asset.type"},
		{"findings | stats count(), avg(cvss_score) as a, p90(epss_score) by severity | top 5 by a",
			"findings | stats count(), avg(cvss_score) as a, p90(epss_score) by severity | top 5 by a"},
		{"assets | bucket first_seen by WEEK | sort first_seen desc, count | limit 10",
			"assets | bucket first_seen by week | sort first_seen desc, count | limit 10"},
		{"findings where related_to = me", "findings where related_to = me"},
		{"findings where is_in_kev = TRUE", "findings where is_in_kev = true"},
	}
	for _, c := range cases {
		q, err := Parse(c.in)
		if err != nil {
			t.Errorf("Parse(%q): %v", c.in, err)
			continue
		}
		got := Format(q)
		if got != c.want {
			t.Errorf("Format(Parse(%q)) = %q, want %q", c.in, got, c.want)
		}
		q2, err := Parse(got)
		if err != nil {
			t.Errorf("reparse %q: %v", got, err)
			continue
		}
		if !reflect.DeepEqual(stripSpans(q), stripSpans(q2)) {
			t.Errorf("round trip changed the tree for %q", c.in)
		}
	}
}

func TestParseErrorPositions(t *testing.T) {
	cases := []struct {
		in         string
		start, end int
		line, col  int
		msg        string
	}{
		{"", 0, 0, 1, 1, "empty"},
		{"findings where", 14, 14, 1, 15, "expected a field name"},
		{"findings where severity", 23, 23, 1, 24, "expected an operator"},
		{"findings where severity = ", 26, 26, 1, 27, "expected a value"},
		{"findings where (severity = critical", 35, 35, 1, 36, `expected ")"`},
		{"findings where severity = critical; DROP TABLE x", 34, 35, 1, 35, "unexpected character"},
		{`findings where title = "unterminated`, 23, 36, 1, 24, "unterminated string"},
		{"findings where a ! 1", 17, 18, 1, 18, `"!" must be followed by "="`},
		{"findings where a = 12abc", 19, 22, 1, 20, "must not be followed by letters"},
		{"findings where a = -14q", 19, 23, 1, 20, "relative time ends in"},
		{"findings\nwhere severity = and", 26, 29, 2, 18, "expected a value"},
		{"findings | frobnicate", 11, 21, 1, 12, "unknown stage"},
		{"findings | bucket created_at by hour", 32, 36, 1, 33, "day, week or month"},
		{"findings | stats mode(x)", 17, 21, 1, 18, "unknown aggregate"},
		{"findings | top x by count", 15, 16, 1, 16, "whole number"},
		{"findings severity = high", 9, 17, 1, 10, `starts with "where"`},
		{"findings where a = 1 b = 2", 21, 22, 1, 22, `join conditions`},
		{"findings where asset.type.x = 1", 25, 26, 1, 26, "at most one relation"},
		{"findings where a = \"\x01\"", 20, 21, 1, 21, "control characters"},
		{"findings where a = 1 | count by", 31, 31, 1, 32, "expected a field name"},
	}
	for _, c := range cases {
		_, err := Parse(c.in)
		qe, ok := AsError(err)
		if !ok {
			t.Errorf("Parse(%q): want *Error, got %v", c.in, err)
			continue
		}
		d := qe.Details[0]
		if d.Start != c.start || d.End != c.end || d.Line != c.line || d.Column != c.col || !strings.Contains(d.Message, c.msg) {
			t.Errorf("Parse(%q) = [%d,%d) %d:%d %q, want [%d,%d) %d:%d ~%q",
				c.in, d.Start, d.End, d.Line, d.Column, d.Message, c.start, c.end, c.line, c.col, c.msg)
		}
	}
}

func TestParseLimits(t *testing.T) {
	long := "findings where text ~ \"" + strings.Repeat("a", MaxQueryBytes) + "\""
	if _, err := Parse(long); err == nil || !strings.Contains(err.Error(), "longer than") {
		t.Errorf("over-long query: %v", err)
	}
	many := "findings where " + strings.Repeat("a = 1 and ", MaxTokens/4) + "a = 1"
	if _, err := Parse(many); err == nil || !strings.Contains(err.Error(), "tokens") {
		t.Errorf("too many tokens: %v", err)
	}
	deep := "findings where " + strings.Repeat("(", MaxNesting+1) + "a = 1" + strings.Repeat(")", MaxNesting+1)
	if _, err := Parse(deep); err == nil || !strings.Contains(err.Error(), "nested too deep") {
		t.Errorf("deep nesting: %v", err)
	}
	nots := "findings where " + strings.Repeat("not ", MaxNesting+1) + "a = 1"
	if _, err := Parse(nots); err == nil || !strings.Contains(err.Error(), "nested too deep") {
		t.Errorf("not chain: %v", err)
	}
	if _, err := Parse("findings where a = \xff"); err == nil || !strings.Contains(err.Error(), "UTF-8") {
		t.Errorf("invalid UTF-8: %v", err)
	}
}

func TestErrorDoesNotEchoStrings(t *testing.T) {
	secret := "s3cr3t-value-in-a-string"
	_, err := Parse(`findings where title = "` + secret + `" "` + secret + `"`)
	if err == nil {
		t.Fatal("want an error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("error echoes a string literal: %v", err)
	}
}
