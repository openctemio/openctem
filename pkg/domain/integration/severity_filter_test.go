package integration

import "testing"

// The severity filter was silently defeating the event-type filter.
//
// DefaultEnabledEventTypes deliberately turns EventTypeApprovalRequested ON,
// with the reasoning recorded next to it: "An approval request is addressed to
// a human; if it reaches nobody the finding stays blocked indefinitely."
//
// The enqueue site stamps Severity: "medium" (vulnerability_service.go), and
// IsSeverityEnabled treats an empty enabled_severities list as critical+high.
// So the event-type gate was opened on purpose and the severity gate closed it
// again — the exact outcome that comment exists to prevent.
//
// These tests pin the two halves together so the same defeat cannot reappear.

func TestSeverityFilter_DoesNotApplyToApprovalEvents(t *testing.T) {
	approvals := []EventType{
		EventTypeApprovalRequested,
		EventTypeApprovalApproved,
		EventTypeApprovalRejected,
	}

	for _, et := range approvals {
		t.Run(string(et), func(t *testing.T) {
			if SeverityFilterApplies(et) {
				t.Fatalf("%s is severity-filtered, but its Severity is a constant "+
					"chosen by the enqueue site, not a finding severity", et)
			}
		})
	}
}

// The filter must keep working for the events it was built for — a fix that
// delivers everything is not a fix.
func TestSeverityFilter_StillAppliesToFindingEvents(t *testing.T) {
	findingShaped := []EventType{
		EventTypeNewFinding,
		EventTypeNewExposure,
		EventTypeFindingAssigned,
		EventTypeFindingPriorityEscalated,
		EventTypeSLABreach,
	}

	for _, et := range findingShaped {
		t.Run(string(et), func(t *testing.T) {
			if !SeverityFilterApplies(et) {
				t.Fatalf("%s stopped being severity-filtered: an operator who asked "+
					"for critical+high only would start receiving everything", et)
			}
		})
	}
}

// The end-to-end statement of the bug: approval_requested is default-ON at the
// event-type gate, and must survive the severity gate on a default (empty)
// configuration.
func TestApprovalRequested_SurvivesBothGatesOnDefaults(t *testing.T) {
	ext := &NotificationExtension{} // empty config = platform defaults

	var defaultOn bool
	for _, et := range DefaultEnabledEventTypes() {
		if et == EventTypeApprovalRequested {
			defaultOn = true
			break
		}
	}
	if !defaultOn {
		t.Fatal("EventTypeApprovalRequested is no longer default-on; if that was " +
			"deliberate, this test should be deleted along with the reasoning " +
			"recorded in DefaultEnabledEventTypes")
	}

	if !ext.ShouldNotifyEventType(EventTypeApprovalRequested) {
		t.Fatal("blocked by the event-type gate")
	}

	// This is the half that was broken: "medium" is not in the default
	// critical+high set, so the severity gate dropped it.
	const enqueuedSeverity = "medium" // vulnerability_service.go RequestApproval
	if ext.ShouldNotify(enqueuedSeverity) {
		t.Fatal("test is not exercising the bug: the default severity set now " +
			"includes medium, so this would pass without the fix")
	}
	if SeverityFilterApplies(EventTypeApprovalRequested) {
		t.Fatal("approval_requested is still severity-filtered, so it is still " +
			"dropped on a default configuration and the finding stays blocked")
	}
}

// Completeness gate. A new event type must be a deliberate decision about
// whether its Severity is a real severity, not a default inherited by whoever
// adds the constant. This fails the build on any unclassified addition.
func TestSeverityFilter_EveryEventTypeIsClassified(t *testing.T) {
	// Severity is a constant at the enqueue site, so filtering it is meaningless.
	notFilterable := map[EventType]bool{
		EventTypeApprovalRequested: true,
		EventTypeApprovalApproved:  true,
		EventTypeApprovalRejected:  true,
	}

	// Severity describes a finding/exposure, so the operator's filter is real.
	filterable := map[EventType]bool{
		EventTypeSecurityAlert:            true,
		EventTypeSystemError:              true,
		EventTypeNewAsset:                 true,
		EventTypeAssetChanged:             true,
		EventTypeAssetDeleted:             true,
		EventTypeScanStarted:              true,
		EventTypeScanCompleted:            true,
		EventTypeScanFailed:               true,
		EventTypeNewFinding:               true,
		EventTypeFindingConfirmed:         true,
		EventTypeFindingTriaged:           true,
		EventTypeFindingFixed:             true,
		EventTypeFindingReopened:          true,
		EventTypeFindingPriorityEscalated: true,
		EventTypeFindingAssigned:          true,
		EventTypeSLABreach:                true,
		EventTypeWorkflowNotification:     true,
		EventTypeNewExposure:              true,
		EventTypeExposureResolved:         true,
	}

	for _, info := range AllEventTypes() {
		et := info.Type
		switch {
		case notFilterable[et]:
			if SeverityFilterApplies(et) {
				t.Errorf("%s is listed as not-filterable here but SeverityFilterApplies says otherwise", et)
			}
		case filterable[et]:
			if !SeverityFilterApplies(et) {
				t.Errorf("%s is listed as filterable here but SeverityFilterApplies says otherwise", et)
			}
		default:
			t.Errorf("event type %q is not classified. Decide whether its "+
				"EnqueueParams.Severity is a real finding severity (add it to "+
				"`filterable`) or a constant picked by the enqueue site (add it to "+
				"`notFilterable` AND to SeverityFilterApplies). Inheriting the "+
				"default silently is how approval_requested became undeliverable.", et)
		}
	}
}
