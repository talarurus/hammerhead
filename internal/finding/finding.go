// Package finding defines the normalized Finding model used across Hammerhead.
//
// Every security check, regardless of its source (native or external tool),
// produces Finding values. Findings are pure data: serializable, sortable,
// and free of filesystem or runtime behavior.
package finding

import (
	"cmp"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
)

// Severity represents potential impact within a finding's class, not verification
// of credential validity, activity, exposure, or compromise.
type Severity int

const (
	SeverityInfo     Severity = iota // Observation, no direct security impact
	SeverityLow                      // Best-practice deviation, minor risk
	SeverityMedium                   // Security hygiene issue that increases risk
	SeverityHigh                     // Likely security issue requiring attention
	SeverityCritical                 // Potential critical impact; credential activity is unverified
)

var severityNames = [...]string{"info", "low", "medium", "high", "critical"}
var severityLabels = [...]string{"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}

func (s Severity) String() string {
	if int(s) >= 0 && int(s) < len(severityNames) {
		return severityNames[s]
	}
	return "unknown"
}

// Label returns the uppercase display label for the severity.
func (s Severity) Label() string {
	if int(s) >= 0 && int(s) < len(severityLabels) {
		return severityLabels[s]
	}
	return "UNKNOWN"
}

func (s Severity) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

func (s *Severity) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	parsed, err := ParseSeverity(str)
	if err != nil {
		return err
	}
	*s = parsed
	return nil
}

// ParseSeverity converts a string to a Severity value.
func ParseSeverity(s string) (Severity, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "info":
		return SeverityInfo, nil
	case "low":
		return SeverityLow, nil
	case "medium":
		return SeverityMedium, nil
	case "high":
		return SeverityHigh, nil
	case "critical":
		return SeverityCritical, nil
	default:
		return SeverityInfo, fmt.Errorf("unknown severity: %q", s)
	}
}

// AllSeverities returns all severity levels from critical (highest) to info (lowest).
func AllSeverities() []Severity {
	return []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo}
}

// Confidence describes certainty in the rule's observation or heuristic,
// not verification of sensitive contents, credential validity, or exposure.
type Confidence int

const (
	ConfidenceLow    Confidence = iota // Heuristic match, may be false positive
	ConfidenceMedium                   // Pattern match with reasonable accuracy
	ConfidenceHigh                     // High-certainty detection
)

var confidenceNames = [...]string{"low", "medium", "high"}

func (c Confidence) String() string {
	if int(c) >= 0 && int(c) < len(confidenceNames) {
		return confidenceNames[c]
	}
	return "unknown"
}

func (c Confidence) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.String())
}

func (c *Confidence) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	switch strings.ToLower(strings.TrimSpace(str)) {
	case "low":
		*c = ConfidenceLow
	case "medium":
		*c = ConfidenceMedium
	case "high":
		*c = ConfidenceHigh
	default:
		return fmt.Errorf("unknown confidence: %q", str)
	}
	return nil
}

// Category classifies what kind of issue a finding represents.
type Category string

const (
	CategorySecrets Category = "secrets"
	CategoryFiles   Category = "files"
	CategoryGit     Category = "git"
	CategoryProject Category = "project"
	CategoryConfig  Category = "config"
)

// FindingClass distinguishes actionable security vulnerabilities from repository hygiene
// and project/informational context.
type FindingClass string

const (
	ClassSecurity FindingClass = "security" // Potential security risks from supported content or filename patterns
	ClassHygiene  FindingClass = "hygiene"  // Best practices, gitignore coverage, README/LICENSE, large files
	ClassInfo     FindingClass = "info"     // Project ecosystem hints, dirty worktree or detached HEAD observations
)

// Finding represents a single security or hygiene finding.
//
// Every field is justified:
//   - ID:          short deterministic identifier; collisions are possible, not a deduplication key
//   - RuleID:      links to the check definition (e.g., "FILE-001")
//   - Class:       categorizes as security, hygiene, or info (drives overall security risk)
//   - Category:    groups findings for reporting
//   - Severity:    severity within the class
//   - Confidence:  prevents pattern-based checks from overstating certainty
//   - Title:       one-line human summary
//   - Description: explains why this matters
//   - Remediation: actionable fix guidance
//   - Path:        location in repository (relative to root)
//   - Line:        specific line number, if applicable
//   - Evidence:    sanitized snippet (secrets redacted)
//   - Source:      provenance ("hammerhead" or future external tool name)
//   - CheckVer:    version of the check that produced this finding
type Finding struct {
	ID          string       `json:"id"`
	RuleID      string       `json:"rule_id"`
	Class       FindingClass `json:"class"`
	Category    Category     `json:"category"`
	Severity    Severity     `json:"severity"`
	Confidence  Confidence   `json:"confidence"`
	Title       string       `json:"title"`
	Description string       `json:"description"`
	Remediation string       `json:"remediation"`
	Path        string       `json:"path,omitempty"`
	Line        int          `json:"line,omitempty"`
	Evidence    string       `json:"evidence,omitempty"`
	Source      string       `json:"source"`
	CheckVer    string       `json:"check_ver"`
}

// AffectsSecurityRisk returns true if the finding represents a direct security issue.
func (f Finding) AffectsSecurityRisk() bool {
	return f.Class == ClassSecurity
}

// GenerateID produces a deterministic instance ID from rule ID and path.
// The same rule + path always produces the same ID. Short hashes can collide;
// findings are not deduplicated by ID.
func GenerateID(ruleID, path string) string {
	h := sha256.Sum256([]byte(ruleID + ":" + path))
	return fmt.Sprintf("%s-%x", ruleID, h[:4])
}

// CompareCanonical orders findings by severity descending, then class, rule,
// slash-normalized path, numeric line, ID, title and remaining scalar fields.
// Raw paths break normalized-path ties without changing stored paths or IDs.
func CompareCanonical(a, b Finding) int {
	if n := cmp.Compare(b.Severity, a.Severity); n != 0 {
		return n
	}
	if n := cmp.Compare(classRank(a.Class), classRank(b.Class)); n != 0 {
		return n
	}
	if n := cmp.Compare(a.RuleID, b.RuleID); n != 0 {
		return n
	}
	if n := cmp.Compare(strings.ReplaceAll(a.Path, "\\", "/"), strings.ReplaceAll(b.Path, "\\", "/")); n != 0 {
		return n
	}
	if n := cmp.Compare(a.Line, b.Line); n != 0 {
		return n
	}
	if n := cmp.Compare(a.ID, b.ID); n != 0 {
		return n
	}
	if n := cmp.Compare(a.Title, b.Title); n != 0 {
		return n
	}
	if n := cmp.Compare(a.Class, b.Class); n != 0 {
		return n
	}
	if n := cmp.Compare(a.Category, b.Category); n != 0 {
		return n
	}
	if n := cmp.Compare(a.Confidence, b.Confidence); n != 0 {
		return n
	}
	if n := cmp.Compare(a.Description, b.Description); n != 0 {
		return n
	}
	if n := cmp.Compare(a.Remediation, b.Remediation); n != 0 {
		return n
	}
	if n := cmp.Compare(a.Evidence, b.Evidence); n != 0 {
		return n
	}
	if n := cmp.Compare(a.Source, b.Source); n != 0 {
		return n
	}
	if n := cmp.Compare(a.CheckVer, b.CheckVer); n != 0 {
		return n
	}
	return cmp.Compare(a.Path, b.Path)
}

func classRank(c FindingClass) int {
	switch c {
	case ClassSecurity:
		return 0
	case ClassHygiene:
		return 1
	case ClassInfo:
		return 2
	default:
		return 3
	}
}

// BySeverity implements sort.Interface using the canonical finding order.
type BySeverity []Finding

func (f BySeverity) Len() int           { return len(f) }
func (f BySeverity) Less(i, j int) bool { return CompareCanonical(f[i], f[j]) < 0 }
func (f BySeverity) Swap(i, j int)      { f[i], f[j] = f[j], f[i] }

// CountBySeverity returns a count of findings at each severity level.
func CountBySeverity(findings []Finding) map[Severity]int {
	counts := make(map[Severity]int)
	for _, f := range findings {
		counts[f.Severity]++
	}
	return counts
}

// MaxSeverity returns the highest severity among all findings.
// Returns SeverityInfo if the slice is empty.
func MaxSeverity(findings []Finding) Severity {
	max := SeverityInfo
	for _, f := range findings {
		if f.Severity > max {
			max = f.Severity
		}
	}
	return max
}

// MaxSecuritySeverity returns the highest severity strictly among findings that
// affect security risk (f.Class == ClassSecurity).
// Returns (SeverityInfo, false) if there are no security findings.
func MaxSecuritySeverity(findings []Finding) (Severity, bool) {
	hasSecurity := false
	max := SeverityInfo
	for _, f := range findings {
		if f.AffectsSecurityRisk() {
			hasSecurity = true
			if f.Severity > max {
				max = f.Severity
			}
		}
	}
	return max, hasSecurity
}

// CountByClass returns counts of findings grouped by FindingClass.
func CountByClass(findings []Finding) map[FindingClass]int {
	counts := make(map[FindingClass]int)
	for _, f := range findings {
		counts[f.Class]++
	}
	return counts
}

// AboveThreshold returns findings at or above the given severity.
func AboveThreshold(findings []Finding, threshold Severity) []Finding {
	var result []Finding
	for _, f := range findings {
		if f.Severity >= threshold {
			result = append(result, f)
		}
	}
	return result
}
