package audit

// The refresh-token rotation grace (docs/architecture/session-refresh.md).

const (
	// ActionAuthRefreshGrace records that a refresh token already rotated was
	// accepted again within the grace and its successor handed out a second
	// time (two tabs of one browser, or a client that missed the rotation).
	ActionAuthRefreshGrace Action = "auth.refresh_grace"
)

var _ = registerActions("auth", map[Action]Severity{
	ActionAuthRefreshGrace: SeverityLow,
})
