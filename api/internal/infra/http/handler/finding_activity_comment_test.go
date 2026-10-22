package handler

import "testing"

func TestHideDeletedCommentText(t *testing.T) {
	deleted := map[string]bool{"c1": true}
	for _, typ := range []string{"comment_added", "comment_updated"} {
		in := FindingActivityResponse{ActivityType: typ, Changes: map[string]any{
			"comment_id": "c1", "content": "secret words", "preview": "secret", "previous_content": "older", "visibility": "team",
		}}
		out := hideDeletedCommentText(in, deleted)
		for _, k := range []string{"content", "preview", "previous_content"} {
			if _, ok := out.Changes[k]; ok {
				t.Errorf("%s: %s still present for a deleted comment", typ, k)
			}
		}
		if out.Changes["deleted"] != true || out.Changes["comment_id"] != "c1" {
			t.Errorf("%s: placeholder markers missing: %v", typ, out.Changes)
		}
		if _, ok := in.Changes["content"]; !ok {
			t.Errorf("%s: the stored entry was modified", typ)
		}
	}
	live := FindingActivityResponse{ActivityType: "comment_added", Changes: map[string]any{"comment_id": "c2", "content": "kept"}}
	if got := hideDeletedCommentText(live, deleted); got.Changes["content"] != "kept" {
		t.Error("a live comment lost its text")
	}
}

func TestClientSafeActivity_CommentRevisionsKeepOnlyClientKeys(t *testing.T) {
	a := FindingActivityResponse{ActivityType: "comment_updated", Changes: map[string]any{
		"comment_id": "c1", "content": "new", "previous_content": "old", "visibility": "client",
	}}
	out := clientSafeActivity(a)
	if _, ok := out.Changes["previous_content"]; ok {
		t.Error("a campaign client must not read the previous text")
	}
	if out.Changes["content"] != "new" {
		t.Error("the client's current text is missing")
	}
}
