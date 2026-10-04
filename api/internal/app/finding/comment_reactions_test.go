package finding

import (
	"context"
	"errors"
	"sort"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/activity"
	"github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/datascope"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// --- fakes -------------------------------------------------------------------

type reactFindingRepo struct {
	vulnerability.FindingRepository
	byID    map[string]*vulnerability.Finding // tenant/id
	members map[string]bool                   // campaign/user
}

func (r *reactFindingRepo) GetByID(_ context.Context, tenantID, id shared.ID) (*vulnerability.Finding, error) {
	f, ok := r.byID[tenantID.String()+"/"+id.String()]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return f, nil
}

func (r *reactFindingRepo) IsPentestCampaignMember(_ context.Context, _, campaignID, userID string) (bool, error) {
	return r.members[campaignID+"/"+userID], nil
}

type reactCommentRepo struct {
	vulnerability.FindingCommentRepository
	byID    map[string]*vulnerability.FindingComment
	created []*vulnerability.FindingComment
}

func (r *reactCommentRepo) GetByTenantAndID(_ context.Context, tenantID, id shared.ID) (*vulnerability.FindingComment, error) {
	c, ok := r.byID[id.String()]
	if !ok || c.TenantID() != tenantID {
		return nil, shared.ErrNotFound
	}
	return c, nil
}

func (r *reactCommentRepo) Create(_ context.Context, c *vulnerability.FindingComment) error {
	r.created = append(r.created, c)
	r.byID[c.ID().String()] = c
	return nil
}

type reactionKey struct {
	comment, user shared.ID
	emoji         string
}

// memReactionRepo mirrors the postgres repository: a UNIQUE key and the
// domain cap check.
type memReactionRepo struct {
	rows []reactionKey
	adds int
	dels int
}

func (m *memReactionRepo) Add(_ context.Context, _, commentID, userID shared.ID, emoji string) (bool, error) {
	m.adds++
	emojiUsed, distinct, mine := false, map[string]bool{}, 0
	for _, r := range m.rows {
		if r.comment != commentID {
			continue
		}
		if r.user == userID && r.emoji == emoji {
			return false, nil
		}
		distinct[r.emoji] = true
		if r.emoji == emoji {
			emojiUsed = true
		}
		if r.user == userID {
			mine++
		}
	}
	if err := vulnerability.CheckReactionCaps(emojiUsed, len(distinct), mine); err != nil {
		return false, err
	}
	m.rows = append(m.rows, reactionKey{commentID, userID, emoji})
	return true, nil
}

func (m *memReactionRepo) Remove(_ context.Context, _, commentID, userID shared.ID, emoji string) (bool, error) {
	m.dels++
	for i, r := range m.rows {
		if r.comment == commentID && r.user == userID && r.emoji == emoji {
			m.rows = append(m.rows[:i], m.rows[i+1:]...)
			return true, nil
		}
	}
	return false, nil
}

func (m *memReactionRepo) Summaries(_ context.Context, _ shared.ID, commentIDs []shared.ID, viewer shared.ID) (map[shared.ID][]vulnerability.ReactionSummary, error) {
	out := map[shared.ID][]vulnerability.ReactionSummary{}
	for _, cid := range commentIDs {
		idx := map[string]int{}
		for _, r := range m.rows { // rows are in insertion (first-use) order
			if r.comment != cid {
				continue
			}
			i, ok := idx[r.emoji]
			if !ok {
				out[cid] = append(out[cid], vulnerability.ReactionSummary{Emoji: r.emoji})
				i = len(out[cid]) - 1
				idx[r.emoji] = i
			}
			s := &out[cid][i]
			s.Count++
			s.ReactedByMe = s.ReactedByMe || r.user == viewer
			s.SampleUsers = append(s.SampleUsers, vulnerability.ReactionUser{ID: r.user})
		}
	}
	return out, nil
}

type countingAuditor struct{ events []audit.AuditEvent }

func (a *countingAuditor) LogEvent(_ context.Context, _ audit.AuditContext, e audit.AuditEvent) error {
	a.events = append(a.events, e)
	return nil
}

type recordingBroadcaster struct{ events []map[string]any }

func (b *recordingBroadcaster) BroadcastActivity(_ string, data any, _ string) {
	b.events = append(b.events, data.(map[string]any))
}

// scopeRepo denies every asset to users that have a scope assignment.
type denyScopeRepo struct{}

func (denyScopeRepo) HasAnyScopeAssignment(context.Context, shared.ID, shared.ID) (bool, error) {
	return true, nil
}
func (denyScopeRepo) AssetIDsInScope(context.Context, shared.ID, shared.ID, []shared.ID) ([]shared.ID, error) {
	return nil, nil
}
func (denyScopeRepo) FindingAssetID(context.Context, shared.ID, shared.ID) (shared.ID, error) {
	return shared.ID{}, shared.ErrNotFound
}
func (denyScopeRepo) FindingIDsInScope(context.Context, shared.ID, shared.ID, []shared.ID) ([]shared.ID, error) {
	return nil, nil
}
func (denyScopeRepo) HasFullDataRole(context.Context, shared.ID, shared.ID) (bool, error) {
	return false, nil
}
func (denyScopeRepo) AssetIDsInTenant(context.Context, shared.ID, []shared.ID) ([]shared.ID, error) {
	return nil, nil
}

// --- fixture -----------------------------------------------------------------

type reactFixture struct {
	svc       *VulnerabilityService
	findings  *reactFindingRepo
	comments  *reactCommentRepo
	reactions *memReactionRepo
	auditor   *countingAuditor
	bcast     *recordingBroadcaster
	tenantID  shared.ID
	finding   *vulnerability.Finding
	comment   *vulnerability.FindingComment
	member    shared.ID
}

func newReactFixture(t *testing.T) *reactFixture {
	t.Helper()
	f := &reactFixture{
		findings:  &reactFindingRepo{byID: map[string]*vulnerability.Finding{}, members: map[string]bool{}},
		comments:  &reactCommentRepo{byID: map[string]*vulnerability.FindingComment{}},
		reactions: &memReactionRepo{},
		auditor:   &countingAuditor{},
		bcast:     &recordingBroadcaster{},
		tenantID:  shared.NewID(),
		member:    shared.NewID(),
	}
	fnd, err := vulnerability.NewFinding(f.tenantID, shared.NewID(), vulnerability.FindingSourceSAST, "semgrep",
		vulnerability.SeverityHigh, "SQL injection")
	if err != nil {
		t.Fatal(err)
	}
	f.finding = fnd
	f.findings.byID[f.tenantID.String()+"/"+fnd.ID().String()] = fnd
	c, err := vulnerability.NewFindingComment(f.tenantID, fnd.ID(), shared.NewID(), "looks real")
	if err != nil {
		t.Fatal(err)
	}
	f.comment = c
	f.comments.byID[c.ID().String()] = c

	log := logger.NewNop()
	f.svc = NewVulnerabilityService(nil, f.findings, log)
	f.svc.SetCommentRepository(f.comments)
	f.svc.SetCommentReactionRepository(f.reactions)
	f.svc.SetAuditService(f.auditor)
	act := activity.NewFindingActivityService(nil, f.findings, log)
	act.SetBroadcaster(f.bcast)
	f.svc.activityService = act
	return f
}

func (f *reactFixture) input(emoji string) CommentReactionInput {
	return CommentReactionInput{
		TenantID:     f.tenantID.String(),
		CommentID:    f.comment.ID().String(),
		Emoji:        emoji,
		UserID:       f.member.String(),
		ActingUserID: f.member.String(),
	}
}

// --- tests -------------------------------------------------------------------

func TestCommentReaction_AddIsIdempotentAndRemoveToggles(t *testing.T) {
	f := newReactFixture(t)
	ctx := context.Background()

	got, err := f.svc.AddCommentReaction(ctx, f.input("👀"))
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if len(got) != 1 || got[0].Emoji != "👀" || got[0].Count != 1 || !got[0].ReactedByMe {
		t.Fatalf("after add: %+v", got)
	}

	// Adding the same reaction again changes nothing (the UNIQUE key).
	got, err = f.svc.AddCommentReaction(ctx, f.input("👀"))
	if err != nil {
		t.Fatalf("second add: %v", err)
	}
	if len(got) != 1 || got[0].Count != 1 || len(f.reactions.rows) != 1 {
		t.Fatalf("second add changed state: %+v rows=%d", got, len(f.reactions.rows))
	}
	if len(f.bcast.events) != 1 {
		t.Fatalf("broadcasts after idempotent add = %d, want 1", len(f.bcast.events))
	}
	ev := f.bcast.events[0]
	if ev["type"] != "reactions_updated" || ev["comment_id"] != f.comment.ID().String() ||
		ev["finding_id"] != f.finding.ID().String() || len(ev) != 3 {
		t.Fatalf("broadcast event = %v", ev)
	}

	got, err = f.svc.RemoveCommentReaction(ctx, f.input("👀"))
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("after remove: %+v", got)
	}
	// Removing again is a no-op.
	if _, err := f.svc.RemoveCommentReaction(ctx, f.input("👀")); err != nil {
		t.Fatalf("second remove: %v", err)
	}
	if len(f.bcast.events) != 2 {
		t.Fatalf("broadcasts = %d, want 2", len(f.bcast.events))
	}
	if len(f.auditor.events) != 0 {
		t.Fatalf("plain add/remove wrote %d audit entries, want 0", len(f.auditor.events))
	}
}

func TestCommentReaction_OrderByFirstUse(t *testing.T) {
	f := newReactFixture(t)
	ctx := context.Background()
	for _, e := range []string{"🎉", "👍", "👀"} {
		if _, err := f.svc.AddCommentReaction(ctx, f.input(e)); err != nil {
			t.Fatal(err)
		}
	}
	other := f.input("👀")
	other.UserID = shared.NewID().String()
	got, err := f.svc.AddCommentReaction(ctx, other)
	if err != nil {
		t.Fatal(err)
	}
	var order []string
	for _, s := range got {
		order = append(order, s.Emoji)
	}
	if len(order) != 3 || order[0] != "🎉" || order[1] != "👍" || order[2] != "👀" {
		t.Fatalf("order = %v, want first-use order", order)
	}
	if got[2].Count != 2 || !got[2].ReactedByMe || got[0].ReactedByMe {
		t.Fatalf("👀 for the other viewer = %+v", got[2])
	}
}

func TestCommentReaction_InvalidEmojiRefused(t *testing.T) {
	f := newReactFixture(t)
	for _, e := range []string{"", "a", "<b>", "👍👍", "\u200b👍"} {
		_, err := f.svc.AddCommentReaction(context.Background(), f.input(e))
		if !errors.Is(err, vulnerability.ErrReactionInvalidEmoji) {
			t.Errorf("emoji %q: err = %v, want ErrReactionInvalidEmoji", e, err)
		}
	}
	if f.reactions.adds != 0 {
		t.Fatalf("repository reached %d times for invalid emoji", f.reactions.adds)
	}
}

func TestCommentReaction_CrossTenantCommentNotFound(t *testing.T) {
	f := newReactFixture(t)
	in := f.input("👍")
	in.TenantID = shared.NewID().String() // the caller's tenant is another one
	in.IsAdmin = true                     // even an admin of that tenant
	_, err := f.svc.AddCommentReaction(context.Background(), in)
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	if f.reactions.adds != 0 {
		t.Fatal("cross-tenant request reached the repository")
	}
}

func TestCommentReaction_DataScopeDenied(t *testing.T) {
	f := newReactFixture(t)
	f.svc.SetDataScope(datascope.New(denyScopeRepo{}, nil, func(context.Context) datascope.Caller {
		return datascope.Caller{UserID: f.member.String()}
	}, nil))

	// The comment list refuses the same caller the same way.
	_, listErr := f.svc.ListFindingComments(context.Background(), f.tenantID.String(),
		f.finding.ID().String(), f.member.String(), false)
	if !errors.Is(listErr, shared.ErrNotFound) {
		t.Fatalf("list err = %v, want ErrNotFound", listErr)
	}
	_, err := f.svc.AddCommentReaction(context.Background(), f.input("👍"))
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("add err = %v, want ErrNotFound (same as list)", err)
	}
	_, err = f.svc.RemoveCommentReaction(context.Background(), f.input("👍"))
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("remove err = %v, want ErrNotFound", err)
	}
	if f.reactions.adds+f.reactions.dels != 0 {
		t.Fatal("out-of-scope request reached the repository")
	}
}

func TestCommentReaction_PentestNonMemberDenied(t *testing.T) {
	f := newReactFixture(t)
	campaign := shared.NewID()
	pf, err := vulnerability.NewFinding(f.tenantID, shared.NewID(), vulnerability.FindingSourcePentest, "manual",
		vulnerability.SeverityHigh, "IDOR in invoices")
	if err != nil {
		t.Fatal(err)
	}
	pf.SetPentestCampaignID(&campaign)
	f.findings.byID[f.tenantID.String()+"/"+pf.ID().String()] = pf
	pc, err := vulnerability.NewFindingComment(f.tenantID, pf.ID(), shared.NewID(), "repro attached")
	if err != nil {
		t.Fatal(err)
	}
	f.comments.byID[pc.ID().String()] = pc
	f.comment = pc
	f.finding = pf

	_, err = f.svc.AddCommentReaction(context.Background(), f.input("👍"))
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("non-member err = %v, want ErrNotFound", err)
	}

	f.findings.members[campaign.String()+"/"+f.member.String()] = true
	if _, err := f.svc.AddCommentReaction(context.Background(), f.input("👍")); err != nil {
		t.Fatalf("member: %v", err)
	}
}

func TestCommentReaction_DistinctEmojiCap(t *testing.T) {
	f := newReactFixture(t)
	ctx := context.Background()
	emoji := []string{"😀", "😁", "😂", "😃", "😄", "😅", "😆", "😇", "😈", "😉",
		"😊", "😋", "😌", "😍", "😎", "😏", "😐", "😑", "😒", "😓", "😔"}
	// 20 distinct emoji from different people (each well under the per-user cap).
	for i := range vulnerability.MaxDistinctReactionsPerComment {
		in := f.input(emoji[i])
		in.UserID = shared.NewID().String()
		if _, err := f.svc.AddCommentReaction(ctx, in); err != nil {
			t.Fatalf("emoji %d: %v", i, err)
		}
	}
	in := f.input(emoji[20])
	_, err := f.svc.AddCommentReaction(ctx, in)
	if !errors.Is(err, vulnerability.ErrReactionEmojiLimit) || !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("21st distinct emoji err = %v, want ErrReactionEmojiLimit", err)
	}
	// An emoji already on the comment can still be added.
	if _, err := f.svc.AddCommentReaction(ctx, f.input(emoji[0])); err != nil {
		t.Fatalf("existing emoji refused: %v", err)
	}
}

func TestCommentReaction_PerUserCap(t *testing.T) {
	f := newReactFixture(t)
	ctx := context.Background()
	emoji := []string{"🍎", "🍐", "🍊", "🍋", "🍌", "🍉", "🍇", "🍓", "🫐", "🍈", "🍒"}
	for i := range vulnerability.MaxReactionsPerUserPerComment {
		if _, err := f.svc.AddCommentReaction(ctx, f.input(emoji[i])); err != nil {
			t.Fatalf("reaction %d: %v", i, err)
		}
	}
	_, err := f.svc.AddCommentReaction(ctx, f.input(emoji[10]))
	if !errors.Is(err, vulnerability.ErrReactionUserLimit) {
		t.Fatalf("11th reaction err = %v, want ErrReactionUserLimit", err)
	}
}

func TestCommentReaction_ModerationRequiresAdminAndIsAudited(t *testing.T) {
	f := newReactFixture(t)
	ctx := context.Background()
	victim := shared.NewID()
	in := f.input("👍")
	in.UserID = victim.String()
	if _, err := f.svc.AddCommentReaction(ctx, in); err != nil {
		t.Fatal(err)
	}

	// A member cannot remove someone else's reaction.
	mod := f.input("👍")
	mod.TargetUserID = victim.String()
	_, err := f.svc.RemoveCommentReaction(ctx, mod)
	if !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("member moderation err = %v, want ErrForbidden", err)
	}
	if len(f.reactions.rows) != 1 || len(f.auditor.events) != 0 {
		t.Fatal("refused moderation changed state or audited")
	}

	// An admin can, and exactly one audit entry is written.
	mod.IsAdmin = true
	got, err := f.svc.RemoveCommentReaction(ctx, mod)
	if err != nil {
		t.Fatalf("admin moderation: %v", err)
	}
	if len(got) != 0 || len(f.reactions.rows) != 0 {
		t.Fatalf("reaction not removed: %+v", got)
	}
	if len(f.auditor.events) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(f.auditor.events))
	}
	e := f.auditor.events[0]
	if e.Action != auditdom.ActionFindingCommentReactionRemoved || e.ResourceID != f.comment.ID().String() ||
		e.Metadata["reaction_user_id"] != victim.String() {
		t.Fatalf("audit event = %+v", e)
	}

	// Moderating a reaction that is not there writes nothing.
	if _, err := f.svc.RemoveCommentReaction(ctx, mod); err != nil {
		t.Fatal(err)
	}
	// An admin removing their own reaction is a plain removal: not audited.
	own := f.input("👍")
	own.IsAdmin = true
	if _, err := f.svc.AddCommentReaction(ctx, own); err != nil {
		t.Fatal(err)
	}
	own.TargetUserID = f.member.String()
	if _, err := f.svc.RemoveCommentReaction(ctx, own); err != nil {
		t.Fatal(err)
	}
	if len(f.auditor.events) != 1 {
		t.Fatalf("audit entries = %d, want still 1", len(f.auditor.events))
	}
}

func TestAddFindingComment_InternalRoundTrip(t *testing.T) {
	f := newReactFixture(t)
	repo := &recordingActivityRepo{}
	f.svc.activityService = activity.NewFindingActivityService(repo, f.findings, logger.NewNop())

	c, err := f.svc.AddFindingCommentWithInput(context.Background(), AddFindingCommentInput{
		TenantID: f.tenantID.String(), FindingID: f.finding.ID().String(),
		AuthorID: f.member.String(), Content: "internal note", IsInternal: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !c.IsInternal() || !f.comments.created[len(f.comments.created)-1].IsInternal() {
		t.Fatal("is_internal not set on the stored comment")
	}
	if len(repo.created) != 1 || repo.created[0].Changes()["is_internal"] != true {
		t.Fatalf("comment_added activity changes = %v", repo.created[0].Changes())
	}

	pub, err := f.svc.AddFindingComment(context.Background(), f.tenantID.String(),
		f.finding.ID().String(), f.member.String(), "public note")
	if err != nil {
		t.Fatal(err)
	}
	if pub.IsInternal() || repo.created[1].Changes()["is_internal"] != false {
		t.Fatal("plain comment recorded as internal")
	}
}

func TestCommentReactionSummaries_OneCallForManyComments(t *testing.T) {
	f := newReactFixture(t)
	ctx := context.Background()
	c2, _ := vulnerability.NewFindingComment(f.tenantID, f.finding.ID(), shared.NewID(), "second")
	f.comments.byID[c2.ID().String()] = c2
	if _, err := f.svc.AddCommentReaction(ctx, f.input("👍")); err != nil {
		t.Fatal(err)
	}
	in := f.input("🎉")
	in.CommentID = c2.ID().String()
	if _, err := f.svc.AddCommentReaction(ctx, in); err != nil {
		t.Fatal(err)
	}
	got, err := f.svc.CommentReactionSummaries(ctx, f.tenantID.String(),
		[]shared.ID{f.comment.ID(), c2.ID()}, f.member.String())
	if err != nil {
		t.Fatal(err)
	}
	keys := []string{}
	for k, v := range got {
		keys = append(keys, k.String()+v[0].Emoji)
	}
	sort.Strings(keys)
	if len(got) != 2 || got[f.comment.ID()][0].Emoji != "👍" || got[c2.ID()][0].Emoji != "🎉" {
		t.Fatalf("summaries = %v", keys)
	}
}

// recordingActivityRepo keeps created activities.
type recordingActivityRepo struct {
	vulnerability.FindingActivityRepository
	created []*vulnerability.FindingActivity
}

func (r *recordingActivityRepo) Create(_ context.Context, a *vulnerability.FindingActivity) error {
	r.created = append(r.created, a)
	return nil
}
