package coverage

import (
	"testing"
	"time"
)

func TestApplyInfoPolicy(t *testing.T) {
	rules := []Rule{
		{Capability: "vuln.templates", Every: 7 * 24 * time.Hour},
		{Capability: CapabilityVulnTemplatesInfo, Every: 30 * 24 * time.Hour},
	}
	if got := ApplyInfoPolicy(rules, InfoPolicy{On: false, Every: time.Hour}); len(got) != 1 || got[0].Capability != "vuln.templates" {
		t.Errorf("off: %+v", got)
	}
	got := ApplyInfoPolicy(rules, InfoPolicy{On: true, Every: 9 * 24 * time.Hour})
	if len(got) != 2 || got[1].Every != 9*24*time.Hour || got[0].Every != 7*24*time.Hour {
		t.Errorf("interval: %+v", got)
	}
	if rules[1].Every != 30*24*time.Hour {
		t.Error("the input rules were changed")
	}
}

func TestStageKeyOf(t *testing.T) {
	if StageKeyOf(CapabilityVulnTemplatesInfo) != "vuln.templates" || StageKeyOf("scan.ports") != "scan.ports" {
		t.Error("stage key mapping")
	}
	if !ValidCapability(CapabilityVulnTemplatesInfo) {
		t.Error("the info key is not a valid capability")
	}
}

func TestInfoRuleIsInTheRegistry(t *testing.T) {
	var regular, info bool
	for _, r := range RulesFor("service", "http") {
		regular = regular || r.Capability == "vuln.templates"
		info = info || r.Capability == CapabilityVulnTemplatesInfo
	}
	if !regular || !info {
		t.Errorf("http service rules: regular %v, info %v", regular, info)
	}
}
