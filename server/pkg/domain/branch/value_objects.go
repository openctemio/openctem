package branch

// Type represents the branch type.
type Type string

const (
	TypeMain    Type = "main"
	TypeDevelop Type = "develop"
	TypeFeature Type = "feature"
	TypeRelease Type = "release"
	TypeHotfix  Type = "hotfix"
	TypeOther   Type = "other"
)

func (t Type) String() string {
	return string(t)
}

func (t Type) IsValid() bool {
	switch t {
	case TypeMain, TypeDevelop, TypeFeature, TypeRelease, TypeHotfix, TypeOther:
		return true
	default:
		return false
	}
}

func ParseType(s string) Type {
	switch s {
	case "main", "master":
		return TypeMain
	case "develop", "development", "dev":
		return TypeDevelop
	case "feature":
		return TypeFeature
	case "release":
		return TypeRelease
	case "hotfix":
		return TypeHotfix
	default:
		return TypeOther
	}
}

// ScanStatus represents the branch scan status.
type ScanStatus string

const (
	ScanStatusPassed     ScanStatus = "passed"
	ScanStatusFailed     ScanStatus = "failed"
	ScanStatusWarning    ScanStatus = "warning"
	ScanStatusScanning   ScanStatus = "scanning"
	ScanStatusNotScanned ScanStatus = "not_scanned"
)

func (s ScanStatus) String() string {
	return string(s)
}

func (s ScanStatus) IsValid() bool {
	switch s {
	case ScanStatusPassed, ScanStatusFailed, ScanStatusWarning, ScanStatusScanning, ScanStatusNotScanned:
		return true
	default:
		return false
	}
}

func ParseScanStatus(s string) ScanStatus {
	switch s {
	case "passed":
		return ScanStatusPassed
	case "failed":
		return ScanStatusFailed
	case "warning":
		return ScanStatusWarning
	case "scanning":
		return ScanStatusScanning
	default:
		return ScanStatusNotScanned
	}
}

// QualityGateStatus represents the quality gate status.
type QualityGateStatus string

const (
	QualityGatePassed      QualityGateStatus = "passed"
	QualityGateFailed      QualityGateStatus = "failed"
	QualityGateWarning     QualityGateStatus = "warning"
	QualityGateNotComputed QualityGateStatus = "not_computed"
)

func (q QualityGateStatus) String() string {
	return string(q)
}

func (q QualityGateStatus) IsValid() bool {
	switch q {
	case QualityGatePassed, QualityGateFailed, QualityGateWarning, QualityGateNotComputed:
		return true
	default:
		return false
	}
}

func ParseQualityGateStatus(s string) QualityGateStatus {
	switch s {
	case "passed":
		return QualityGatePassed
	case "failed":
		return QualityGateFailed
	case "warning":
		return QualityGateWarning
	default:
		return QualityGateNotComputed
	}
}
