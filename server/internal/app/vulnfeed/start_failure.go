package vulnfeed

import (
	"context"
	"net/url"

	"github.com/openctemio/openctem/server/internal/app/feedstatus"
	"github.com/openctemio/openctem/server/pkg/domain/threatintel"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// SettingBaseURL names the server setting a start-up refusal is about.
const SettingBaseURL = "VULNFEED_BASE_URL"

// RecordStartFailure stores why the importer could not be built at start-up
// (NewImporter refused the server's feed address), so the console card and
// the freshness watch say so instead of one log line: a blocked address is
// blocked_address, any other refusal config_invalid. The params name the
// setting and the host (never a path, query or credential). The data held
// is kept; the import stays off until the setting is fixed and the API
// restarted.
func RecordStartFailure(ctx context.Context, status threatintel.SyncStatusRepository, baseURL string, cause error) error {
	st, err := status.GetBySource(ctx, SourceName)
	if err != nil {
		return err
	}
	c := feedstatus.Classify(cause)
	if c.Code != feedstatus.CodeBlockedAddress {
		c.Code = feedstatus.CodeConfigInvalid
	}
	params := map[string]string{"setting": SettingBaseURL}
	if u, perr := url.Parse(baseURL); perr == nil && u.Hostname() != "" {
		params["host"] = u.Hostname()
	}
	st.MarkSyncFailedWith(logger.RedactURLs(cause.Error()), c.Code, params)
	return status.Update(ctx, st)
}
