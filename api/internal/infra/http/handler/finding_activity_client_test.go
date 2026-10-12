package handler

import "testing"

// A campaign client's activity feed keeps the status move and a shared
// comment's text, never the team's reasons, notes or source metadata.
func TestClientSafeActivity(t *testing.T) {
	status := clientSafeActivity(FindingActivityResponse{
		ActivityType:   "status_changed",
		Changes:        map[string]any{"old_status": "confirmed", "new_status": "accepted", "reason": "client will never fix this"},
		SourceMetadata: map[string]any{"ip": "198.51.100.7"},
	})
	if _, ok := status.Changes["reason"]; ok || status.Changes["new_status"] != "accepted" || status.SourceMetadata != nil {
		t.Fatalf("status change for a client: %+v", status)
	}
	comment := clientSafeActivity(FindingActivityResponse{
		ActivityType: "comment_added",
		Changes:      map[string]any{"content": "fixed?", "visibility": "client", "client_name": "x", "is_internal": false},
	})
	if comment.Changes["content"] != "fixed?" || comment.Changes["client_name"] != nil {
		t.Fatalf("comment for a client: %+v", comment)
	}
	retest := clientSafeActivity(FindingActivityResponse{
		ActivityType: "retest_requested",
		Changes:      map[string]any{"note": "team note", "new_status": "fix_applied"},
	})
	if _, ok := retest.Changes["note"]; ok {
		t.Fatalf("retest request note for a client: %+v", retest)
	}
}
