package postgres

import (
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// What a signed job pinned is stored on its command under its own tenant
// and read back on the run's tasks; another tenant cannot write it, a retry
// overwrites it, and a task that pinned nothing has none. Against the real
// SQL (migration tenant_wordlists_and_content_pins).
func TestCommandContentPins_RecordAndRead(t *testing.T) {
	f := newRunTasksFixture(t)
	run := seedCounterRun(f.ctx, t, f.runs, f.tenant, f.scan)
	enum := f.command(t, f.tenant, run.ID, nil, "pending", map[string]any{"scanner": "dnsx-enum", "targets": []string{"example.com"}})
	plain := f.command(t, f.tenant, run.ID, nil, "pending", map[string]any{"scanner": "httpx", "targets": []string{"example.com"}})
	repo := NewCommandContentPinsRepository(&DB{DB: f.db})

	pins := &scanrun.ContentPins{
		Packs: []scanrun.PinnedPack{{Slot: "labels", Scope: "platform", Pack: "wordlists-s", Version: "2026.10.1",
			Digest: "sha256:31d496ecafd463a37af1cf2161a7be634d6e6ceafb6539c8b891aba665945fdb"}},
		Inputs: []scanrun.PinnedInput{{Slot: "labels", Purpose: "dns-labels", Source: scanrun.InputSourceOrganization, SHA256: "ab", Lines: 3,
			Lists: []scanrun.PinnedList{{ID: "l1", Name: "branches", Version: 2, SHA256: "cd"}}}},
	}
	if err := repo.RecordContentPins(f.ctx, f.tenant, enum, pins); err != nil {
		t.Fatal(err)
	}
	// Another tenant's write reaches nothing.
	other := seedTestTenant(f.ctx, t, f.db)
	if err := repo.RecordContentPins(f.ctx, other, enum, &scanrun.ContentPins{Packs: []scanrun.PinnedPack{{Pack: "forged"}}}); err != nil {
		t.Fatal(err)
	}

	tasks, _, err := f.cmds.ListRunTasks(f.ctx, f.tenant, run.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	byID := map[shared.ID]scanrun.Task{}
	for _, task := range tasks {
		byID[task.ID] = task
	}
	got := byID[enum].ContentPins
	if got == nil || len(got.Packs) != 1 || got.Packs[0].Version != "2026.10.1" || got.Packs[0].Pack != "wordlists-s" ||
		len(got.Inputs) != 1 || got.Inputs[0].Lists[0].Name != "branches" {
		t.Fatalf("pins read back %+v", got)
	}
	if byID[plain].ContentPins != nil {
		t.Fatalf("a task that pinned nothing has %+v", byID[plain].ContentPins)
	}

	// A retry overwrites the record.
	pins.Packs[0].Version = "2026.11.1"
	if err := repo.RecordContentPins(f.ctx, f.tenant, enum, pins); err != nil {
		t.Fatal(err)
	}
	tasks, _, _ = f.cmds.ListRunTasks(f.ctx, f.tenant, run.ID, 0)
	for _, task := range tasks {
		if task.ID == enum && task.ContentPins.Packs[0].Version != "2026.11.1" {
			t.Fatalf("retry not recorded: %+v", task.ContentPins)
		}
	}
}

// The detection rule sets a report was matched with join the command's
// pins without dropping what signing wrote; another tenant cannot write
// them; a command signing pinned nothing gets them too.
func TestCommandContentPins_RulePins(t *testing.T) {
	f := newRunTasksFixture(t)
	run := seedCounterRun(f.ctx, t, f.runs, f.tenant, f.scan)
	signed := f.command(t, f.tenant, run.ID, nil, "pending", map[string]any{"scanner": "dnsx-enum", "targets": []string{"example.com"}})
	plain := f.command(t, f.tenant, run.ID, nil, "pending", map[string]any{"scanner": "httpx", "targets": []string{"example.com"}})
	repo := NewCommandContentPinsRepository(&DB{DB: f.db})
	if err := repo.RecordContentPins(f.ctx, f.tenant, signed, &scanrun.ContentPins{
		Packs: []scanrun.PinnedPack{{Slot: "labels", Scope: "platform", Pack: "wordlists-s", Version: "2026.10.1", Digest: "sha256:aa"}},
	}); err != nil {
		t.Fatal(err)
	}
	rules := []scanrun.PinnedRules{
		{Kind: "web-fingerprints", Scope: "platform", Pack: "web-fingerprints-core", Version: "2026.10.1", Digest: "sha256:bb", Rules: 40},
		{Kind: "secret-rules", Scope: "organization", Digest: "sha256:cc", Rules: 2},
	}
	for _, id := range []shared.ID{signed, plain} {
		if err := repo.RecordRulePins(f.ctx, f.tenant, id, rules); err != nil {
			t.Fatal(err)
		}
	}
	other := seedTestTenant(f.ctx, t, f.db)
	if err := repo.RecordRulePins(f.ctx, other, signed, []scanrun.PinnedRules{{Kind: "secret-rules", Pack: "forged"}}); err != nil {
		t.Fatal(err)
	}
	tasks, _, err := f.cmds.ListRunTasks(f.ctx, f.tenant, run.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, task := range tasks {
		p := task.ContentPins
		switch task.ID {
		case signed:
			if p == nil || len(p.Packs) != 1 || len(p.Rules) != 2 || p.Rules[0].Pack != "web-fingerprints-core" || p.Rules[1].Rules != 2 {
				t.Fatalf("signed command pins = %+v", p)
			}
		case plain:
			if p == nil || len(p.Packs) != 0 || len(p.Rules) != 2 {
				t.Fatalf("plain command pins = %+v", p)
			}
		}
	}
}
