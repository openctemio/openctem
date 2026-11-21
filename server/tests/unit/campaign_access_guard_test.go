package unit

// Who is on a pentest campaign team (direct members and the current members
// of granted user groups) is resolved in one place: the view
// pentest_campaign_access, read through pkg/domain/campaignaccess. A reader
// that queries the membership tables itself would miss group grants (or
// honor an ended group membership), so only the files below may name them
// in SQL: the repositories that write the team, the offboarding cleanup,
// and campaign creation (its lead).

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var campaignTeamSQLRe = regexp.MustCompile(`(?i)\b(FROM|JOIN|INTO|UPDATE)\s+(pentest_campaign_members|pentest_campaign_group_grants|pentest_campaign_access(_sources)?)\b`)

var campaignTeamSQLFiles = map[string]bool{
	"internal/infra/postgres/pentest_campaign_member_repository.go":      true, // the team (direct rows + effective reads)
	"internal/infra/postgres/pentest_campaign_group_grant_repository.go": true, // the group grants
	"internal/infra/postgres/pentest_campaign_repository.go":             true, // campaign creation inserts its lead
	"internal/infra/postgres/member_lifecycle_repository.go":             true, // offboarding removes direct rows
}

func TestCampaignTeamReadOnlyThroughCampaignAccess(t *testing.T) {
	const api = "../.."
	found := map[string]bool{}
	for _, dir := range []string{"internal", "pkg", "cmd"} {
		err := filepath.WalkDir(filepath.Join(api, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if campaignTeamSQLRe.Match(b) {
				rel, _ := filepath.Rel(api, path)
				found[filepath.ToSlash(rel)] = true
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	var added, gone []string
	for f := range found {
		if !campaignTeamSQLFiles[f] {
			added = append(added, f)
		}
	}
	for f := range campaignTeamSQLFiles {
		if !found[f] {
			gone = append(gone, f)
		}
	}
	sort.Strings(added)
	sort.Strings(gone)
	for _, f := range added {
		t.Errorf("%s queries the campaign team tables: use campaignaccess (pentest_campaign_access) so group grants count", f)
	}
	for _, f := range gone {
		t.Errorf("%s no longer queries the campaign team tables: remove it from campaignTeamSQLFiles", f)
	}
}
