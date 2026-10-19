// Package product defines the fixed Hammerhead Core product contract.
package product

const Name = "Hammerhead Core"
const Version = "0.2.0-core.1"
const Schema = "hammerhead-core/v0.2"
const BaseCommit = "4fa1018b13ed4b8b6af194a326105e098dc8118f"
const ScopeNotice = "Core only: six native checks. GIT-002: NOT EVALUATED (Git health and metadata collection are omitted)."

type OmittedCheck struct {
	RuleID string `json:"rule_id"`
	Status string `json:"status"`
	Reason string `json:"reason"`
}
type Scope struct {
	IncludedRules     []string       `json:"included_rules"`
	NotEvaluated      []OmittedCheck `json:"not_evaluated"`
	CompletionMeaning string         `json:"completion_meaning"`
}

func CoreScope() Scope {
	return Scope{
		IncludedRules:     []string{"FILE-001", "FILE-002", "GIT-001", "PROJ-001", "PROJ-002", "SEC-001"},
		NotEvaluated:      []OmittedCheck{{RuleID: "GIT-002", Status: "not_evaluated", Reason: "Git health and native Git metadata collection are excluded from Hammerhead Core"}},
		CompletionMeaning: "A completed status means all six Core checks completed under the reported filesystem exclusions and limits; no claim of complete repository security",
	}
}
