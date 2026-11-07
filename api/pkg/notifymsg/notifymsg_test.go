package notifymsg

import (
	"errors"
	"regexp"
	"strings"
	"testing"
)

func TestCatalogLocalesHaveSameKeysAndPlaceholders(t *testing.T) {
	en := catalog[LocaleEN]
	for _, l := range Locales() {
		m := catalog[l]
		if len(m) != len(en) {
			t.Errorf("%s has %d keys, en %d", l, len(m), len(en))
		}
		for k, v := range en {
			lv, ok := m[k]
			if !ok {
				t.Errorf("%s misses %s", l, k)
				continue
			}
			if strings.Contains(v, "{0}") != strings.Contains(lv, "{0}") {
				t.Errorf("%s %s placeholder differs", l, k)
			}
		}
	}
}

func TestParseTemplateRefusesUnknownVariables(t *testing.T) {
	_, err := ParseTemplate("{severity_emoji} [{severity}] {title}\n{url} {body}")
	var unk *UnknownVariablesError
	if !errors.As(err, &unk) || !errors.Is(err, ErrInvalidTemplate) {
		t.Fatalf("want UnknownVariablesError, got %v", err)
	}
	if got := strings.Join(unk.Names, ","); got != "body,severity_emoji,url" {
		t.Fatalf("names %q", got)
	}
}

func TestParseTemplateSyntax(t *testing.T) {
	bad := []string{"{title", "title}", "{Title}", "{ title }", "{}", "{a-b}", strings.Repeat("x", MaxTemplateRunes+1),
		strings.Repeat("x\n", MaxTemplateLines), "{" + strings.Repeat("a", 41) + "}"}
	for _, src := range bad {
		if err := ValidateTemplate(src); !errors.Is(err, ErrInvalidTemplate) {
			t.Errorf("%q: want invalid, got %v", src, err)
		}
	}
	good := []string{"", "  ", "{title} on {asset}", "literal {{braces}} stay", "{what}\n\n{why}"}
	for _, src := range good {
		if err := ValidateTemplate(src); err != nil {
			t.Errorf("%q: %v", src, err)
		}
	}
	tp, _ := ParseTemplate("a {{b}} c")
	if got := tp.Render(nil); len(got) != 1 || got[0] != "a {b} c" {
		t.Fatalf("literal braces: %q", got)
	}
}

func TestRenderDropsLinesWhoseVariablesAreEmpty(t *testing.T) {
	tp, err := ParseTemplate("Asset: {asset}\n\n\nWhat: {what}\nfixed text\n\n")
	if err != nil {
		t.Fatal(err)
	}
	got := tp.Render(map[Var]string{VarWhat: "x"})
	want := []string{"What: x", "fixed text"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestMinimalCardCarriesNoObjectDetails(t *testing.T) {
	in := SampleInput("new_exposure", LevelMinimal, "en", "https://c.example")
	c := Build(in)
	if c.Subject.Name != "" || c.What != "" || c.Why != "" || c.Description != "" {
		t.Fatalf("minimal card leaks: %+v", c)
	}
	if c.Headline != "New exposure" || c.Severity != "high" || c.Organization != "Example Corp" || c.Action.URL == "" {
		t.Fatalf("minimal card: %+v", c)
	}
	// A template cannot reach above the level.
	c, ok := ApplyTemplate(c, "{asset}\n{what}\n{description}\n{title} for {organization}")
	if !ok || strings.Join(c.Custom, "|") != "New exposure for Example Corp" {
		t.Fatalf("template on minimal: %q", c.Custom)
	}
}

func TestStandardAndFullLevels(t *testing.T) {
	std := Build(SampleInput("new_finding", LevelStandard, "en", ""))
	if std.Subject.Name != "shop.example.com" || !strings.Contains(std.What, "CVE-2026-12345") ||
		!strings.Contains(std.Why, "CISA KEV") || !strings.Contains(std.Why, "EPSS 42%") || std.Description != "" {
		t.Fatalf("standard: %+v", std)
	}
	if std.NextStep != T("en", "next.finding.kev") {
		t.Fatalf("next step %q", std.NextStep)
	}
	full := Build(SampleInput("new_finding", LevelFull, "en", ""))
	if full.Description == "" {
		t.Fatal("full lost the description")
	}
	exp := Build(SampleInput("new_exposure", LevelStandard, "vi", ""))
	if exp.Headline != "Điểm phơi nhiễm mới" || !strings.Contains(exp.What, "giao diện web bị lộ") {
		t.Fatalf("vi exposure: %+v", exp)
	}
}

func TestLinesAreOrderedAndHaveNoEmptyValues(t *testing.T) {
	c := Build(SampleInput("new_exposure", LevelStandard, "en", ""))
	var keys []string
	for _, l := range c.Lines() {
		if strings.TrimSpace(l.Value) == "" {
			t.Fatalf("empty line %+v", l)
		}
		keys = append(keys, l.Key)
	}
	if got := strings.Join(keys, ","); got != "severity,asset,what,why,next_step,organization" {
		t.Fatalf("order %s", got)
	}
	// Severity is shown once in the text, the headline once.
	text := c.Headline + "\n" + c.Text()
	if strings.Count(text, "High") != 1 || strings.Count(text, "New exposure") != 1 {
		t.Fatalf("repeats:\n%s", text)
	}
}

var uuidPattern = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-`)

func TestProducerTextLosesSeverityWordsAndIDs(t *testing.T) {
	c := Build(Input{EventType: "sensor.offline", Severity: "high", Level: LevelFull,
		ProducerTitle: "Sensor 0192f3c4-1111-7abc-8def-0123456789ab offline (high)",
		ProducerBody:  "id 0192f3c4-1111-7abc-8def-0123456789ab stopped"})
	if uuidPattern.MatchString(c.What+c.Description) || strings.Contains(strings.ToLower(c.What), "high") {
		t.Fatalf("what %q desc %q", c.What, c.Description)
	}
	if got := stripSeverityWords("New high exposure: open port"); got != "New exposure: open port" {
		t.Fatalf("strip %q", got)
	}
}

func TestParseLevel(t *testing.T) {
	for _, s := range []string{"minimal", "Standard", " full "} {
		if _, err := ParseLevel(s); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
	if _, err := ParseLevel("everything"); err == nil {
		t.Fatal("unknown level accepted")
	}
	if Build(Input{Level: "bogus", Facts: &Facts{AssetName: "x"}}).Subject.Name != "" {
		t.Fatal("unknown level must act as minimal")
	}
}

func TestValidationMessageNeverCarriesLowerErrorText(t *testing.T) {
	_, levelErr := ParseLevel("loud")
	cases := map[string]error{
		"unknown variables": ValidateTemplate("{nope} {gone}"),
		"bad template":      ValidateTemplate("{unclosed"),
		"bad level":         levelErr,
	}
	for name, err := range cases {
		if err == nil {
			t.Fatalf("%s: want an error", name)
		}
		msg := ValidationMessage(err)
		if msg == "" || strings.Contains(msg, err.Error()) || strings.Contains(msg, "loud") {
			t.Errorf("%s: message %q echoes the error text %q", name, msg, err.Error())
		}
	}
	if got := ValidationMessage(ValidateTemplate("{nope}")); !strings.Contains(got, "nope") {
		t.Errorf("unknown variable name should be listed, got %q", got)
	}
}
