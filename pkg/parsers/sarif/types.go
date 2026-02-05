// Package sarif provides types and parser for SARIF (Static Analysis Results Interchange Format) v2.1.0.
// SARIF is an OASIS standard for representing static analysis results.
// Specification: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
package sarif

// Log represents the root SARIF log object.
type Log struct {
	Version string `json:"version"`
	Schema  string `json:"$schema,omitempty"`
	Runs    []Run  `json:"runs"`
}

// Run represents a single run of an analysis tool.
type Run struct {
	Tool        Tool         `json:"tool"`
	Results     []Result     `json:"results,omitempty"`
	Invocations []Invocation `json:"invocations,omitempty"`
	Artifacts   []Artifact   `json:"artifacts,omitempty"`
	Properties  Properties   `json:"properties,omitempty"`
}

// Tool describes the analysis tool that produced the results.
type Tool struct {
	Driver     ToolComponent   `json:"driver"`
	Extensions []ToolComponent `json:"extensions,omitempty"`
}

// ToolComponent represents a component of an analysis tool (driver or extension).
type ToolComponent struct {
	Name             string                    `json:"name"`
	Version          string                    `json:"version,omitempty"`
	SemanticVersion  string                    `json:"semanticVersion,omitempty"`
	InformationURI   string                    `json:"informationUri,omitempty"`
	Rules            []ReportingDescriptor     `json:"rules,omitempty"`
	Notifications    []ReportingDescriptor     `json:"notifications,omitempty"`
	Properties       Properties                `json:"properties,omitempty"`
	GUID             string                    `json:"guid,omitempty"`
	Organization     string                    `json:"organization,omitempty"`
	Product          string                    `json:"product,omitempty"`
	FullName         string                    `json:"fullName,omitempty"`
	ShortDescription *MultiformatMessageString `json:"shortDescription,omitempty"`
	FullDescription  *MultiformatMessageString `json:"fullDescription,omitempty"`
}

// ReportingDescriptor describes a rule or notification produced by a tool.
type ReportingDescriptor struct {
	ID                   string                    `json:"id"`
	Name                 string                    `json:"name,omitempty"`
	ShortDescription     *MultiformatMessageString `json:"shortDescription,omitempty"`
	FullDescription      *MultiformatMessageString `json:"fullDescription,omitempty"`
	Help                 *MultiformatMessageString `json:"help,omitempty"`
	HelpURI              string                    `json:"helpUri,omitempty"`
	DefaultConfiguration *ReportingConfiguration   `json:"defaultConfiguration,omitempty"`
	Properties           Properties                `json:"properties,omitempty"`
}

// ReportingConfiguration specifies the default configuration for a rule.
type ReportingConfiguration struct {
	Enabled    bool       `json:"enabled,omitempty"`
	Level      Level      `json:"level,omitempty"`
	Rank       float64    `json:"rank,omitempty"`
	Parameters Properties `json:"parameters,omitempty"`
}

// Result represents a single result from the analysis.
type Result struct {
	RuleID              string                        `json:"ruleId,omitempty"`
	RuleIndex           int                           `json:"ruleIndex,omitempty"`
	Rule                *ReportingDescriptorReference `json:"rule,omitempty"`
	Kind                Kind                          `json:"kind,omitempty"`
	Level               Level                         `json:"level,omitempty"`
	Message             Message                       `json:"message"`
	Locations           []Location                    `json:"locations,omitempty"`
	RelatedLocations    []Location                    `json:"relatedLocations,omitempty"`
	CodeFlows           []CodeFlow                    `json:"codeFlows,omitempty"`
	Fixes               []Fix                         `json:"fixes,omitempty"`
	Fingerprints        map[string]string             `json:"fingerprints,omitempty"`
	PartialFingerprints map[string]string             `json:"partialFingerprints,omitempty"`
	Properties          Properties                    `json:"properties,omitempty"`
	Suppressions        []Suppression                 `json:"suppressions,omitempty"`
	BaselineState       BaselineState                 `json:"baselineState,omitempty"`
	Rank                float64                       `json:"rank,omitempty"`
	HostedViewerURI     string                        `json:"hostedViewerUri,omitempty"`
	GUID                string                        `json:"guid,omitempty"`
	CorrelationGUID     string                        `json:"correlationGuid,omitempty"`
	OccurrenceCount     int                           `json:"occurrenceCount,omitempty"`
}

// ReportingDescriptorReference identifies a rule by ID or index.
type ReportingDescriptorReference struct {
	ID            string                  `json:"id,omitempty"`
	Index         int                     `json:"index,omitempty"`
	GUID          string                  `json:"guid,omitempty"`
	ToolComponent *ToolComponentReference `json:"toolComponent,omitempty"`
}

// ToolComponentReference identifies a tool component.
type ToolComponentReference struct {
	Name  string `json:"name,omitempty"`
	Index int    `json:"index,omitempty"`
	GUID  string `json:"guid,omitempty"`
}

// Location represents a location in an artifact.
type Location struct {
	ID               int               `json:"id,omitempty"`
	PhysicalLocation *PhysicalLocation `json:"physicalLocation,omitempty"`
	LogicalLocations []LogicalLocation `json:"logicalLocations,omitempty"`
	Message          *Message          `json:"message,omitempty"`
	Properties       Properties        `json:"properties,omitempty"`
}

// PhysicalLocation represents a physical location in an artifact.
type PhysicalLocation struct {
	ArtifactLocation *ArtifactLocation `json:"artifactLocation,omitempty"`
	Region           *Region           `json:"region,omitempty"`
	ContextRegion    *Region           `json:"contextRegion,omitempty"`
	Properties       Properties        `json:"properties,omitempty"`
}

// ArtifactLocation represents the location of an artifact.
type ArtifactLocation struct {
	URI         string     `json:"uri,omitempty"`
	URIBaseID   string     `json:"uriBaseId,omitempty"`
	Index       int        `json:"index,omitempty"`
	Description *Message   `json:"description,omitempty"`
	Properties  Properties `json:"properties,omitempty"`
}

// Region represents a region within an artifact.
type Region struct {
	StartLine      int              `json:"startLine,omitempty"`
	StartColumn    int              `json:"startColumn,omitempty"`
	EndLine        int              `json:"endLine,omitempty"`
	EndColumn      int              `json:"endColumn,omitempty"`
	CharOffset     int              `json:"charOffset,omitempty"`
	CharLength     int              `json:"charLength,omitempty"`
	ByteOffset     int              `json:"byteOffset,omitempty"`
	ByteLength     int              `json:"byteLength,omitempty"`
	Snippet        *ArtifactContent `json:"snippet,omitempty"`
	Message        *Message         `json:"message,omitempty"`
	SourceLanguage string           `json:"sourceLanguage,omitempty"`
	Properties     Properties       `json:"properties,omitempty"`
}

// ArtifactContent represents the content of an artifact.
type ArtifactContent struct {
	Text       string                    `json:"text,omitempty"`
	Binary     string                    `json:"binary,omitempty"`
	Rendered   *MultiformatMessageString `json:"rendered,omitempty"`
	Properties Properties                `json:"properties,omitempty"`
}

// LogicalLocation represents a logical location (e.g., function, class).
type LogicalLocation struct {
	Name               string     `json:"name,omitempty"`
	Index              int        `json:"index,omitempty"`
	FullyQualifiedName string     `json:"fullyQualifiedName,omitempty"`
	DecoratedName      string     `json:"decoratedName,omitempty"`
	ParentIndex        int        `json:"parentIndex,omitempty"`
	Kind               string     `json:"kind,omitempty"`
	Properties         Properties `json:"properties,omitempty"`
}

// Message represents a message to the user.
type Message struct {
	Text       string     `json:"text,omitempty"`
	Markdown   string     `json:"markdown,omitempty"`
	ID         string     `json:"id,omitempty"`
	Arguments  []string   `json:"arguments,omitempty"`
	Properties Properties `json:"properties,omitempty"`
}

// MultiformatMessageString represents a message in multiple formats.
type MultiformatMessageString struct {
	Text       string     `json:"text"`
	Markdown   string     `json:"markdown,omitempty"`
	Properties Properties `json:"properties,omitempty"`
}

// CodeFlow describes the execution path that leads to a result.
type CodeFlow struct {
	Message     *Message     `json:"message,omitempty"`
	ThreadFlows []ThreadFlow `json:"threadFlows"`
	Properties  Properties   `json:"properties,omitempty"`
}

// ThreadFlow represents a sequence of code locations in a single thread.
type ThreadFlow struct {
	ID         string               `json:"id,omitempty"`
	Message    *Message             `json:"message,omitempty"`
	Locations  []ThreadFlowLocation `json:"locations"`
	Properties Properties           `json:"properties,omitempty"`
}

// ThreadFlowLocation represents a location in a thread flow.
type ThreadFlowLocation struct {
	Index            int        `json:"index,omitempty"`
	Location         *Location  `json:"location,omitempty"`
	State            Properties `json:"state,omitempty"`
	NestingLevel     int        `json:"nestingLevel,omitempty"`
	ExecutionOrder   int        `json:"executionOrder,omitempty"`
	ExecutionTimeUTC string     `json:"executionTimeUtc,omitempty"`
	Importance       Importance `json:"importance,omitempty"`
	Properties       Properties `json:"properties,omitempty"`
}

// Fix represents a proposed fix for a result.
type Fix struct {
	Description     *Message         `json:"description,omitempty"`
	ArtifactChanges []ArtifactChange `json:"artifactChanges"`
	Properties      Properties       `json:"properties,omitempty"`
}

// ArtifactChange represents changes to a single artifact.
type ArtifactChange struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Replacements     []Replacement    `json:"replacements"`
	Properties       Properties       `json:"properties,omitempty"`
}

// Replacement represents a replacement of content in an artifact.
type Replacement struct {
	DeletedRegion   Region           `json:"deletedRegion"`
	InsertedContent *ArtifactContent `json:"insertedContent,omitempty"`
	Properties      Properties       `json:"properties,omitempty"`
}

// Suppression represents a suppression of a result.
type Suppression struct {
	Kind          SuppressionKind   `json:"kind"`
	Status        SuppressionStatus `json:"status,omitempty"`
	Location      *Location         `json:"location,omitempty"`
	GUID          string            `json:"guid,omitempty"`
	Justification string            `json:"justification,omitempty"`
	Properties    Properties        `json:"properties,omitempty"`
}

// Invocation describes a single invocation of an analysis tool.
type Invocation struct {
	CommandLine                    string             `json:"commandLine,omitempty"`
	Arguments                      []string           `json:"arguments,omitempty"`
	ResponseFiles                  []ArtifactLocation `json:"responseFiles,omitempty"`
	StartTimeUTC                   string             `json:"startTimeUtc,omitempty"`
	EndTimeUTC                     string             `json:"endTimeUtc,omitempty"`
	ExecutionSuccessful            bool               `json:"executionSuccessful"`
	Machine                        string             `json:"machine,omitempty"`
	Account                        string             `json:"account,omitempty"`
	ProcessID                      int                `json:"processId,omitempty"`
	WorkingDirectory               *ArtifactLocation  `json:"workingDirectory,omitempty"`
	EnvironmentVariables           map[string]string  `json:"environmentVariables,omitempty"`
	ToolExecutionNotifications     []Notification     `json:"toolExecutionNotifications,omitempty"`
	ToolConfigurationNotifications []Notification     `json:"toolConfigurationNotifications,omitempty"`
	ExitCode                       int                `json:"exitCode,omitempty"`
	ExitCodeDescription            string             `json:"exitCodeDescription,omitempty"`
	ExitSignalName                 string             `json:"exitSignalName,omitempty"`
	ExitSignalNumber               int                `json:"exitSignalNumber,omitempty"`
	ProcessStartFailureMessage     string             `json:"processStartFailureMessage,omitempty"`
	StdIn                          *ArtifactLocation  `json:"stdin,omitempty"`
	StdOut                         *ArtifactLocation  `json:"stdout,omitempty"`
	StdErr                         *ArtifactLocation  `json:"stderr,omitempty"`
	Properties                     Properties         `json:"properties,omitempty"`
}

// Notification represents a notification produced during the run.
type Notification struct {
	Message        Message                       `json:"message"`
	Level          Level                         `json:"level,omitempty"`
	Locations      []Location                    `json:"locations,omitempty"`
	TimeUTC        string                        `json:"timeUtc,omitempty"`
	Exception      *Exception                    `json:"exception,omitempty"`
	Descriptor     *ReportingDescriptorReference `json:"descriptor,omitempty"`
	AssociatedRule *ReportingDescriptorReference `json:"associatedRule,omitempty"`
	Properties     Properties                    `json:"properties,omitempty"`
}

// Exception describes a runtime exception encountered during analysis.
type Exception struct {
	Kind            string      `json:"kind,omitempty"`
	Message         string      `json:"message,omitempty"`
	Stack           *Stack      `json:"stack,omitempty"`
	InnerExceptions []Exception `json:"innerExceptions,omitempty"`
	Properties      Properties  `json:"properties,omitempty"`
}

// Stack represents a call stack.
type Stack struct {
	Message    *Message     `json:"message,omitempty"`
	Frames     []StackFrame `json:"frames"`
	Properties Properties   `json:"properties,omitempty"`
}

// StackFrame represents a single frame in a call stack.
type StackFrame struct {
	Location   *Location  `json:"location,omitempty"`
	Module     string     `json:"module,omitempty"`
	ThreadID   int        `json:"threadId,omitempty"`
	Parameters []string   `json:"parameters,omitempty"`
	Properties Properties `json:"properties,omitempty"`
}

// Artifact describes an artifact that was analyzed.
type Artifact struct {
	Location            *ArtifactLocation `json:"location,omitempty"`
	ParentIndex         int               `json:"parentIndex,omitempty"`
	Offset              int               `json:"offset,omitempty"`
	Length              int               `json:"length,omitempty"`
	Roles               []ArtifactRole    `json:"roles,omitempty"`
	MimeType            string            `json:"mimeType,omitempty"`
	Contents            *ArtifactContent  `json:"contents,omitempty"`
	Encoding            string            `json:"encoding,omitempty"`
	SourceLanguage      string            `json:"sourceLanguage,omitempty"`
	Hashes              map[string]string `json:"hashes,omitempty"`
	LastModifiedTimeUTC string            `json:"lastModifiedTimeUtc,omitempty"`
	Description         *Message          `json:"description,omitempty"`
	Properties          Properties        `json:"properties,omitempty"`
}

// Properties is a property bag for custom properties.
type Properties map[string]any

// Level represents the severity level of a result.
type Level string

const (
	LevelNone    Level = "none"
	LevelNote    Level = "note"
	LevelWarning Level = "warning"
	LevelError   Level = "error"
)

// IsValid checks if the level is valid.
func (l Level) IsValid() bool {
	switch l {
	case LevelNone, LevelNote, LevelWarning, LevelError, "":
		return true
	default:
		return false
	}
}

// Kind represents the kind of a result.
type Kind string

const (
	KindNotApplicable Kind = "notApplicable"
	KindPass          Kind = "pass"
	KindFail          Kind = "fail"
	KindReview        Kind = "review"
	KindOpen          Kind = "open"
	KindInformational Kind = "informational"
)

// IsValid checks if the kind is valid.
func (k Kind) IsValid() bool {
	switch k {
	case KindNotApplicable, KindPass, KindFail, KindReview, KindOpen, KindInformational, "":
		return true
	default:
		return false
	}
}

// BaselineState represents the baseline state of a result.
type BaselineState string

const (
	BaselineStateNew       BaselineState = "new"
	BaselineStateUnchanged BaselineState = "unchanged"
	BaselineStateUpdated   BaselineState = "updated"
	BaselineStateAbsent    BaselineState = "absent"
)

// Importance represents the importance of a thread flow location.
type Importance string

const (
	ImportanceImportant   Importance = "important"
	ImportanceEssential   Importance = "essential"
	ImportanceUnimportant Importance = "unimportant"
)

// SuppressionKind represents the kind of suppression.
type SuppressionKind string

const (
	SuppressionKindInSource SuppressionKind = "inSource"
	SuppressionKindExternal SuppressionKind = "external"
)

// SuppressionStatus represents the status of a suppression.
type SuppressionStatus string

const (
	SuppressionStatusAccepted    SuppressionStatus = "accepted"
	SuppressionStatusUnderReview SuppressionStatus = "underReview"
	SuppressionStatusRejected    SuppressionStatus = "rejected"
)

// ArtifactRole represents the role of an artifact.
type ArtifactRole string

const (
	ArtifactRoleAnalysisTarget             ArtifactRole = "analysisTarget"
	ArtifactRoleAttachment                 ArtifactRole = "attachment"
	ArtifactRoleResponseFile               ArtifactRole = "responseFile"
	ArtifactRoleResultFile                 ArtifactRole = "resultFile"
	ArtifactRoleStandardStream             ArtifactRole = "standardStream"
	ArtifactRoleTracedFile                 ArtifactRole = "tracedFile"
	ArtifactRoleUnmodified                 ArtifactRole = "unmodified"
	ArtifactRoleModified                   ArtifactRole = "modified"
	ArtifactRoleAdded                      ArtifactRole = "added"
	ArtifactRoleDeleted                    ArtifactRole = "deleted"
	ArtifactRoleRenamed                    ArtifactRole = "renamed"
	ArtifactRoleUncontrolled               ArtifactRole = "uncontrolled"
	ArtifactRoleDriver                     ArtifactRole = "driver"
	ArtifactRoleExtension                  ArtifactRole = "extension"
	ArtifactRoleTranslation                ArtifactRole = "translation"
	ArtifactRoleTaxonomy                   ArtifactRole = "taxonomy"
	ArtifactRolePolicy                     ArtifactRole = "policy"
	ArtifactRoleReferencedOnCommandLine    ArtifactRole = "referencedOnCommandLine"
	ArtifactRoleMemoryContents             ArtifactRole = "memoryContents"
	ArtifactRoleDirectory                  ArtifactRole = "directory"
	ArtifactRoleUserSpecifiedConfiguration ArtifactRole = "userSpecifiedConfiguration"
	ArtifactRoleToolSpecifiedConfiguration ArtifactRole = "toolSpecifiedConfiguration"
	ArtifactRoleDebugOutputFile            ArtifactRole = "debugOutputFile"
)
