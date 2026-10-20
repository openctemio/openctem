package ticketlink

import (
	"strings"
	"testing"
)

func TestSanitizeExternalName(t *testing.T) {
	for in, want := range map[string]string{
		"Dana K.":                        "Dana K.",
		"<img src=x onerror=alert(1)>Al": "Al",
		"a<b":                            "ab",
		"‮evil‬ name\x00":                "evil name",
		"two\nlines\tand  spaces":        "two lines and spaces",
	} {
		if got := SanitizeExternalName(in); got != want {
			t.Errorf("SanitizeExternalName(%q) = %q, want %q", in, got, want)
		}
	}
	if got := SanitizeExternalName(strings.Repeat("x", 1000)); len([]rune(got)) != MaxExternalAssigneeName {
		t.Errorf("length %d, want capped at %d", len([]rune(got)), MaxExternalAssigneeName)
	}
	if got := SanitizeExternalID(" 5b10 ac8d​\n" + strings.Repeat("a", 200)); strings.ContainsAny(got, " \n​") || len(got) > MaxExternalAssigneeID {
		t.Errorf("SanitizeExternalID = %q", got)
	}
}

func TestStatusCategoryFromJira(t *testing.T) {
	for in, want := range map[string]string{"new": StatusCategoryTodo, "indeterminate": StatusCategoryInProgress, "Done": StatusCategoryDone, "x": ""} {
		if got := StatusCategoryFromJira(in); got != want {
			t.Errorf("%q = %q, want %q", in, got, want)
		}
	}
}
