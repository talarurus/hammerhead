package fs

// PresenceFact represents the known presence of a file or directory at the root.
type PresenceFact int

const (
	PresenceUnknown PresenceFact = iota
	PresencePresent
	PresenceAbsent
)

// String returns the string representation of the presence fact.
func (p PresenceFact) String() string {
	switch p {
	case PresencePresent:
		return "PRESENT"
	case PresenceAbsent:
		return "ABSENT"
	default:
		return "UNKNOWN"
	}
}

// Inventory exposes immutable facts about the filesystem traversal.
type Inventory struct {
	ExaminedEntries   int
	RetainedFiles     int
	RetainedDirs      int
	InventoryComplete bool
	DepthExhausted    bool
	RootListComplete  bool
	SkipCounts        map[SkipCategory]int

	RootREADME    PresenceFact
	RootLICENSE   PresenceFact
	RootGitignore PresenceFact
}
