package handler

import "testing"

func TestCSVSafeNeutralisesFormulas(t *testing.T) {
	for in, want := range map[string]string{
		"=HYPERLINK(\"http://x\")": "'=HYPERLINK(\"http://x\")",
		"+1":                       "'+1",
		"-2+3":                     "'-2+3",
		"@SUM(A1)":                 "'@SUM(A1)",
		"\tx":                      "'\tx",
		"\rx":                      "'\rx",
		"plain":                    "plain",
		"":                         "",
		"a=b":                      "a=b",
	} {
		if got := csvSafe(in); got != want {
			t.Errorf("csvSafe(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestExportSlotIsExclusive(t *testing.T) {
	if !acquireExportSlot("t:u") {
		t.Fatal("first slot")
	}
	if acquireExportSlot("t:u") {
		t.Fatal("a second export for the same user must be refused")
	}
	if !acquireExportSlot("t:other") {
		t.Fatal("another user is independent")
	}
	releaseExportSlot("t:u")
	releaseExportSlot("t:other")
	if !acquireExportSlot("t:u") {
		t.Fatal("released slot")
	}
	releaseExportSlot("t:u")
}
