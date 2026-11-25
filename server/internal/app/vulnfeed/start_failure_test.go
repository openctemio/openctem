package vulnfeed

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/internal/app/feedstatus"
	"github.com/openctemio/openctem/server/pkg/domain/threatintel"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// A feed address the server refuses at start-up is a feed status error the
// console shows, not only a log line: a private address is blocked_address,
// anything else config_invalid, with the setting and host named.
func TestRecordStartFailure(t *testing.T) {
	for name, tc := range map[string]struct {
		base string
		code string
	}{
		"private address": {"https://10.20.30.40/releases", feedstatus.CodeBlockedAddress},
		"metadata host":   {"https://169.254.169.254/releases", feedstatus.CodeBlockedAddress},
		"not https":       {"http://mirror.example.com/releases", feedstatus.CodeConfigInvalid},
	} {
		_, err := NewImporter(Config{RootKeyID: "SHA256:x", BaseURL: tc.base}, &fakeCorpus{}, &fakeStatus{}, fakeCatalog{}, logger.NewNop())
		if err == nil {
			t.Fatalf("%s: importer accepted %s", name, tc.base)
		}
		fs := &fakeStatus{st: threatintel.NewSyncStatus(SourceName, 24)}
		if rerr := RecordStartFailure(context.Background(), fs, tc.base, err); rerr != nil {
			t.Fatal(rerr)
		}
		v := feedstatus.Build(fs.st, 0, time.Now())
		if v.State != feedstatus.StateFailing || v.ErrorCode != tc.code {
			t.Errorf("%s: state %s code %q, want failing %q", name, v.State, v.ErrorCode, tc.code)
		}
		if v.ErrorParams["setting"] != SettingBaseURL || v.ErrorParams["host"] == "" {
			t.Errorf("%s: params %v", name, v.ErrorParams)
		}
		if v.FailingSince == nil {
			t.Errorf("%s: failing since not set", name)
		}
	}
}
