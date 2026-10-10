package scanstate

// GitSnapshot is pure metadata collected once by engine orchestration. It
// grants no filesystem or subprocess authority to checks. Unknown values are
// explicit: an unavailable or incomplete snapshot never means a clean tree.
type GitSnapshot struct {
	Availability   GitAvailability
	Applicability  GitApplicability
	Status         CheckStatus
	Root           string
	Branch         string
	BranchState    GitBranchState
	ModifiedCount  int
	UntrackedCount int
}

type GitAvailability string

const (
	GitAvailable           GitAvailability = "available"
	GitUnavailable         GitAvailability = "unavailable"
	GitAvailabilityUnknown GitAvailability = "unknown"
)

type GitApplicability string

const (
	GitRoot                 GitApplicability = "root"
	GitSubdirectory         GitApplicability = "subdirectory"
	GitNonRepository        GitApplicability = "non_repository"
	GitApplicabilityUnknown GitApplicability = "unknown"
)

type GitBranchState string

const (
	GitBranchNormal   GitBranchState = "normal"
	GitBranchUnborn   GitBranchState = "unborn"
	GitBranchDetached GitBranchState = "detached"
	GitBranchUnknown  GitBranchState = "unknown"
)
