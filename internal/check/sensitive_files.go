package check

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/ammaarrehman/hammerhead/internal/finding"
)

// SensitiveFileCheck matches filenames associated with potentially sensitive content.
// It does not read contents or establish credential validity, tracking, or exposure.
// Confidence describes the filename heuristic, not verified sensitive contents.
type SensitiveFileCheck struct{}

// sensitivePattern defines a single filename pattern to match.
type sensitivePattern struct {
	// match is the matching function. Returns true if the filename matches.
	match func(name, lower string) bool

	severity   finding.Severity
	confidence finding.Confidence
	title      string
	desc       string
	remediate  string
}

// sensitivePatterns is the curated list of sensitive file patterns.
//
// Design principles:
//   - Only include patterns with clear security implications
//   - Set confidence honestly: filename-only detection has limits
//   - Every pattern must have actionable remediation
//   - Prefer false negatives over false positives
var sensitivePatterns = []sensitivePattern{
	// === Private key files (high confidence, high severity) ===
	{
		match:      exactName("id_rsa"),
		severity:   finding.SeverityHigh,
		confidence: finding.ConfidenceHigh,
		title:      "Potential SSH private key file",
		desc:       "The filename matches id_rsa, a name commonly used for SSH private keys. This is a filename-only match; contents were not inspected.",
		remediate:  "Review the actual contents. If sensitive information is present, keep it outside version control and add an appropriate ignore pattern. Determine whether exposure occurred before deciding on credential rotation or other recovery steps.",
	},
	{
		match:      exactName("id_dsa"),
		severity:   finding.SeverityHigh,
		confidence: finding.ConfidenceHigh,
		title:      "Potential SSH private key file (DSA)",
		desc:       "The filename matches id_dsa, a name commonly used for DSA SSH private keys. This is a filename-only match; contents were not inspected.",
		remediate:  "Review the actual contents. If sensitive information is present, keep it outside version control and add an appropriate ignore pattern. Determine whether exposure occurred before deciding on credential rotation or other recovery steps.",
	},
	{
		match:      exactName("id_ecdsa"),
		severity:   finding.SeverityHigh,
		confidence: finding.ConfidenceHigh,
		title:      "Potential SSH private key file (ECDSA)",
		desc:       "The filename matches id_ecdsa, a name commonly used for ECDSA SSH private keys. This is a filename-only match; contents were not inspected.",
		remediate:  "Review the actual contents. If sensitive information is present, keep it outside version control and add an appropriate ignore pattern. Determine whether exposure occurred before deciding on credential rotation or other recovery steps.",
	},
	{
		match:      exactName("id_ed25519"),
		severity:   finding.SeverityHigh,
		confidence: finding.ConfidenceHigh,
		title:      "Potential SSH private key file (Ed25519)",
		desc:       "The filename matches id_ed25519, a name commonly used for Ed25519 SSH private keys. This is a filename-only match; contents were not inspected.",
		remediate:  "Review the actual contents. If sensitive information is present, keep it outside version control and add an appropriate ignore pattern. Determine whether exposure occurred before deciding on credential rotation or other recovery steps.",
	},
	{
		match:      hasExtension(".pem"),
		severity:   finding.SeverityHigh,
		confidence: finding.ConfidenceMedium,
		title:      "Potential PEM key or certificate file",
		desc:       "The filename has a .pem extension, which may indicate a private key, a public certificate, or other data. This is a filename-only match; contents were not inspected.",
		remediate:  "Review the actual contents. If sensitive information is present, keep it outside version control and add an appropriate ignore pattern. Determine whether exposure occurred before deciding on credential rotation or other recovery steps.",
	},
	{
		match:      hasExtension(".key"),
		severity:   finding.SeverityHigh,
		confidence: finding.ConfidenceMedium,
		title:      "Potential private key file",
		desc:       "The filename has a .key extension, which may indicate a private key or unrelated data. This is a filename-only match; contents were not inspected.",
		remediate:  "Review the actual contents. If sensitive information is present, keep it outside version control and add an appropriate ignore pattern. Determine whether exposure occurred before deciding on credential rotation or other recovery steps.",
	},
	{
		match:      hasAnyExtension(".p12", ".pfx"),
		severity:   finding.SeverityHigh,
		confidence: finding.ConfidenceHigh,
		title:      "Potential PKCS#12 keystore file",
		desc:       "The filename has a .p12 or .pfx extension, which may indicate a keystore. This is a filename-only match; contents were not inspected.",
		remediate:  "Review the actual contents. If sensitive information is present, keep it outside version control and add an appropriate ignore pattern. Determine whether exposure occurred before deciding on credential rotation or other recovery steps.",
	},
	{
		match:      hasAnyExtension(".jks", ".keystore"),
		severity:   finding.SeverityHigh,
		confidence: finding.ConfidenceMedium,
		title:      "Potential Java keystore file",
		desc:       "The filename has a .jks or .keystore extension, which may indicate a Java keystore. This is a filename-only match; contents were not inspected.",
		remediate:  "Review the actual contents. If sensitive information is present, keep it outside version control and add an appropriate ignore pattern. Determine whether exposure occurred before deciding on credential rotation or other recovery steps.",
	},

	// === Environment and credential files (high confidence, medium severity) ===
	{
		match:      exactDotEnv,
		severity:   finding.SeverityMedium,
		confidence: finding.ConfidenceHigh,
		title:      "Potential environment configuration file",
		desc:       "The filename matches a supported .env naming pattern, which may indicate environment configuration. This is a filename-only match; contents were not inspected.",
		remediate:  "Review the actual contents. If sensitive information is present, keep it outside version control and add an appropriate ignore pattern. Determine whether exposure occurred before deciding on credential rotation or other recovery steps.",
	},
	{
		match:      exactName(".htpasswd"),
		severity:   finding.SeverityMedium,
		confidence: finding.ConfidenceHigh,
		title:      "Potential Apache password file",
		desc:       "The filename matches .htpasswd, a name commonly used for HTTP authentication password hashes. This is a filename-only match; contents were not inspected.",
		remediate:  "Review the actual contents. If sensitive information is present, keep it outside version control and add an appropriate ignore pattern. Determine whether exposure occurred before deciding on credential rotation or other recovery steps.",
	},
	{
		match:      exactNameAny(".netrc", "_netrc"),
		severity:   finding.SeverityMedium,
		confidence: finding.ConfidenceHigh,
		title:      "Potential Netrc credentials file",
		desc:       "The filename matches .netrc or _netrc, names commonly used for remote-host login configuration. This is a filename-only match; contents were not inspected.",
		remediate:  "Review the actual contents. If sensitive information is present, keep it outside version control and add an appropriate ignore pattern. Determine whether exposure occurred before deciding on credential rotation or other recovery steps.",
	},
	{
		match:      exactName(".pgpass"),
		severity:   finding.SeverityMedium,
		confidence: finding.ConfidenceHigh,
		title:      "Potential PostgreSQL password file",
		desc:       "The filename matches .pgpass, a name commonly used for PostgreSQL connection credentials. This is a filename-only match; contents were not inspected.",
		remediate:  "Review the actual contents. If sensitive information is present, keep it outside version control and add an appropriate ignore pattern. Determine whether exposure occurred before deciding on credential rotation or other recovery steps.",
	},
	{
		match:      exactNameAny(".npmrc", ".pypirc"),
		severity:   finding.SeverityMedium,
		confidence: finding.ConfidenceMedium,
		title:      "Potential package manager credentials file",
		desc:       "The filename matches .npmrc or .pypirc, names used for package manager configuration that may include authentication tokens. This is a filename-only match; contents were not inspected.",
		remediate:  "Review the actual contents. If sensitive information is present, keep it outside version control and add an appropriate ignore pattern. Determine whether exposure occurred before deciding on credential rotation or other recovery steps.",
	},

	// === Configuration that may contain secrets (medium confidence) ===
	{
		match:      nameContainsNonCode("credentials"),
		severity:   finding.SeverityMedium,
		confidence: finding.ConfidenceMedium,
		title:      "Potential credentials file",
		desc:       "The filename contains credentials, which may indicate authentication data. This is a filename-only match; contents were not inspected.",
		remediate:  "Review the actual contents. If sensitive information is present, keep it outside version control and add an appropriate ignore pattern. Determine whether exposure occurred before deciding on credential rotation or other recovery steps.",
	},
	{
		match:      nameContainsNonCode("secret"),
		severity:   finding.SeverityMedium,
		confidence: finding.ConfidenceLow,
		title:      "Potential secrets file",
		desc:       "The filename contains secret, which may indicate sensitive configuration. This is a filename-only match; contents were not inspected.",
		remediate:  "Review the actual contents. If sensitive information is present, keep it outside version control and add an appropriate ignore pattern. Determine whether exposure occurred before deciding on credential rotation or other recovery steps.",
	},
}

const (
	sensitiveCheckID      = "FILE-001"
	sensitiveCheckName    = "sensitive-file-detection"
	sensitiveCheckVersion = "0.2.0"
)

func (c *SensitiveFileCheck) Meta() Meta {
	return Meta{
		ID:          sensitiveCheckID,
		Name:        sensitiveCheckName,
		Category:    finding.CategoryFiles,
		Description: "Matches filenames associated with potentially sensitive content without inspecting their contents",
		Version:     sensitiveCheckVersion,
	}
}

func (c *SensitiveFileCheck) Run(ctx context.Context, sc *ScanContext) error {
	for _, file := range sc.Files {
		if err := ctx.Err(); err != nil {
			return err
		}

		if file.IsDir {
			continue
		}

		if sc.Coverage != nil {
			sc.Coverage.EligibleFiles++
			sc.Coverage.InspectedFiles++
		}

		name := filepath.Base(file.Path)
		lower := strings.ToLower(name)

		for _, pattern := range sensitivePatterns {
			if pattern.match(name, lower) {
				err := sc.Emit(finding.Finding{
					ID:          finding.GenerateID(sensitiveCheckID, file.Path),
					RuleID:      sensitiveCheckID,
					Class:       finding.ClassSecurity,
					Category:    finding.CategoryFiles,
					Severity:    pattern.severity,
					Confidence:  pattern.confidence,
					Title:       pattern.title,
					Description: pattern.desc,
					Remediation: pattern.remediate,
					Path:        file.Path,
					Evidence:    name,
					Source:      "hammerhead",
					CheckVer:    sensitiveCheckVersion,
				})
				if err != nil {
					return err
				}
				break // One finding per file; first matching pattern wins.
			}
		}
	}

	return nil
}

// === Matching helpers ===
// These return closures so patterns are defined declaratively above.

func exactName(target string) func(name, lower string) bool {
	targetLower := strings.ToLower(target)
	return func(_, lower string) bool {
		return lower == targetLower
	}
}

func exactNameAny(targets ...string) func(name, lower string) bool {
	set := make(map[string]bool, len(targets))
	for _, t := range targets {
		set[strings.ToLower(t)] = true
	}
	return func(_, lower string) bool {
		return set[lower]
	}
}

func hasExtension(ext string) func(name, lower string) bool {
	return func(_, lower string) bool {
		return strings.HasSuffix(lower, ext)
	}
}

func hasAnyExtension(exts ...string) func(name, lower string) bool {
	return func(_, lower string) bool {
		for _, ext := range exts {
			if strings.HasSuffix(lower, ext) {
				return true
			}
		}
		return false
	}
}

func nameContains(substr string) func(name, lower string) bool {
	return func(_, lower string) bool {
		return strings.Contains(lower, substr)
	}
}

func nameContainsNonCode(substr string) func(name, lower string) bool {
	return func(_, lower string) bool {
		if !strings.Contains(lower, substr) {
			return false
		}
		// Skip programming language source code files to avoid false positives (e.g. secrets.go)
		ext := filepath.Ext(lower)
		switch ext {
		case ".go", ".rs", ".java", ".c", ".cpp", ".h", ".ts", ".js", ".py", ".rb", ".php", ".cs":
			return false
		}
		return true
	}
}

// exactDotEnv matches .env but not .env.example, .env.template, .env.sample.
func exactDotEnv(_, lower string) bool {
	if lower == ".env" {
		return true
	}
	// Match .env.local, .env.production, etc. but not .env.example/.env.template/.env.sample
	if strings.HasPrefix(lower, ".env.") {
		suffix := lower[5:]
		switch suffix {
		case "example", "template", "sample", "dist":
			return false
		}
		return true
	}
	return false
}
