package automation

// The catalog: every trigger, action and notification type the platform
// runs, in the order a builder offers them. IsValid on each type and the
// GET /api/v1/workflows/catalog answer are built from these lists, so the
// API and the console cannot offer a type the engine does not run.

// TriggerTypes lists every trigger type the platform fires.
func TriggerTypes() []TriggerType {
	return []TriggerType{
		TriggerTypeManual,
		TriggerTypeFindingCreated,
		TriggerTypeFindingStatusChanged,
		TriggerTypeAssetDiscovered,
		TriggerTypeScanCompleted,
		TriggerTypeAITriageCompleted,
		TriggerTypeAITriageFailed,
	}
}

// ActionTypes lists every action type the platform executes.
func ActionTypes() []ActionType {
	return []ActionType{
		ActionTypeAssignUser,
		ActionTypeUpdateStatus,
		ActionTypeAddTags,
		ActionTypeRemoveTags,
		ActionTypeCreateTicket,
		ActionTypeUpdateTicket,
		ActionTypeTriggerScan,
		ActionTypeTriggerAITriage,
		ActionTypeRequestFalsePositive,
		ActionTypeRequestRiskAcceptance,
	}
}

// NotificationTypes lists every notification type the platform delivers.
func NotificationTypes() []NotificationType {
	return []NotificationType{
		NotificationTypeSlack,
		NotificationTypeTeams,
		NotificationTypeEmail,
		NotificationTypeWebhook,
	}
}
