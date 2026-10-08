package scanstate

// Limits defines boundaries for finding production, diagnostics, and payloads.
type Limits struct {
	MaxFindings           int
	MaxDiagnosticSamples  int
	MaxExamplesPerReason  int
	MaxFindingPath        int
	MaxFindingEvidence    int
	MaxFindingTitle       int
	MaxFindingDesc        int
	MaxFindingRemediation int
	MaxDiagnosticPath     int
	MaxSafeMessage        int
	MaxAggregateReadBytes int64
}

// ProductionLimits returns the frozen budget limits for P1-03.
func ProductionLimits() Limits {
	return Limits{
		MaxFindings:           10000,
		MaxDiagnosticSamples:  200,
		MaxExamplesPerReason:  5,
		MaxFindingPath:        16384,
		MaxFindingEvidence:    2048,
		MaxFindingTitle:       8192,
		MaxFindingDesc:        8192,
		MaxFindingRemediation: 8192,
		MaxDiagnosticPath:     16384,
		MaxSafeMessage:        2048,
		MaxAggregateReadBytes: 256 * 1024 * 1024,
	}
}
