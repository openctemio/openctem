package navpin

import (
	"errors"
	"testing"
)

func known(k string) bool { return k == "needs_triage" || k == "sla_breached" }

func TestValidate(t *testing.T) {
	ok := []Pin{
		{KindPage, "/"},
		{KindPage, "/my-work"},
		{KindPage, "/remediation/tasks"},
		{KindQuickView, "needs_triage"},
		{KindSavedView, "01a173dc-e286-74ec-9e80-5f8ae645a7cc"},
	}
	if err := Validate(ok, known); err != nil {
		t.Fatalf("valid list refused: %v", err)
	}
	bad := map[string][]Pin{
		"absolute url":        {{KindPage, "https://evil.example/"}},
		"protocol relative":   {{KindPage, "//evil.example"}},
		"traversal":           {{KindPage, "/findings/../admin"}},
		"query":               {{KindPage, "/findings?x=1"}},
		"upper case":          {{KindPage, "/Findings"}},
		"unknown quick view":  {{KindQuickView, "everything"}},
		"bad saved view id":   {{KindSavedView, "not-an-id"}},
		"unknown kind":        {{Kind("script"), "/"}},
		"duplicate":           {{KindPage, "/"}, {KindPage, "/"}},
		"empty page segments": {{KindPage, "/findings//x"}},
	}
	for name, pins := range bad {
		if err := Validate(pins, known); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
	many := make([]Pin, MaxPins+1)
	for i := range many {
		many[i] = Pin{KindPage, "/p" + string(rune('a'+i))}
	}
	if err := Validate(many, known); !errors.Is(err, ErrInvalid) {
		t.Errorf("%d pins accepted", len(many))
	}
}
