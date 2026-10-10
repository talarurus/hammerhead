package check

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/ammaarrehman/hammerhead/internal/finding"
)

// SensitiveFileCheck detects files with names that indicate sensitive content.
//
// This check matches filenames against a curated list of patterns known to
// contain credentials, private keys, or configuration secrets. It does NOT
// read file contents — it operates purely on filenames.
//
// Confidence is set based on how definitively the filename indicates sensitive
// content. A file named "id_rsa" is high confidence. A file ending in ".sql"
// is lower confidence because it may be a schema file rather than a data dump.
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
		title:      "SSH private key",
		desc:       "An SSH private key file was found. If this is a real key, it may grant unauthorized access to systems.",
		remediate:  "Remove the file from the repository, rotate the key, and add 'id_rsa' to .gitignore. Use ssh-keygen to generate a new key pair.",
	},
	{
		match:      exactName("id_dsa"),
		severity:   finding.SeverityHigh,
		confidence: finding.ConfidenceHigh,
		title:      "SSH private key (DSA)",
		desc:       "A DSA SSH private key file was found. DSA keys are also considered cryptographically weak.",
		remediate:  "Remove the file, rotate the key, and add 'id_dsa' to .gitignore. Consider migrating to Ed25519 keys.",
	},
	{
		match:      exactName("id_ecdsa"),
		severity:   finding.SeverityHigh,
		confidence: finding.ConfidenceHigh,
		title:      "SSH private key (ECDSA)",
		desc:       "An ECDSA SSH private key file was found in the repository.",
		remediate:  "Remove the file, rotate the key, and add 'id_ecdsa' to .gitignore.",
	},
	{
		match:      exactName("id_ed25519"),
		severity:   finding.SeverityHigh,
		confidence: finding.ConfidenceHigh,
		title:      "SSH private key (Ed25519)",
		desc:       "An Ed25519 SSH private key file was found in the repository.",
		remediate:  "Remove the file, rotate the key, and add 'id_ed25519' to .gitignore.",
	},
	{
		match:      hasExtension(".pem"),
		severity:   finding.SeverityHigh,
		confidence: finding.ConfidenceMedium,
		title:      "PEM-encoded key or certificate",
		desc:       "A .pem file was found. PEM files may contain private keys or certificates.",
		remediate:  "Verify whether this file contains a private key. If so, remove it and add '*.pem' to .gitignore.",
	},
	{
		match:      hasExtension(".key"),
		severity:   finding.SeverityHigh,
		confidence: finding.ConfidenceMedium,
		title:      "Private key file",
		desc:       "A .key file was found, which commonly contains private cryptographic keys.",
		remediate:  "Remove the file if it contains a private key and add '*.key' to .gitignore.",
	},
	{
		match:      hasAnyExtension(".p12", ".pfx"),
		severity:   finding.SeverityHigh,
		confidence: finding.ConfidenceHigh,
		title:      "PKCS#12 keystore",
		desc:       "A PKCS#12 keystore was found. These files contain private keys and certificates, often password-protected.",
		remediate:  "Remove the file, rotate the contained keys/certificates, and add '*.p12' and '*.pfx' to .gitignore.",
	},
	{
		match:      hasAnyExtension(".jks", ".keystore"),
		severity:   finding.SeverityHigh,
		confidence: finding.ConfidenceMedium,
		title:      "Java keystore",
		desc:       "A Java keystore file was found. These may contain private keys and certificates.",
		remediate:  "Remove the file if it contains production keys and add the extension to .gitignore.",
	},

	// === Environment and credential files (high confidence, medium severity) ===
	{
		match:      exactDotEnv,
		severity:   finding.SeverityMedium,
		confidence: finding.ConfidenceHigh,
		title:      "Environment configuration file",
		desc:       "A .env file was found. These files typically contain environment variables including API keys, database credentials, and other secrets.",
		remediate:  "Remove the file from the repository, add '.env' to .gitignore, and use a .env.example file with placeholder values instead.",
	},
	{
		match:      exactName(".htpasswd"),
		severity:   finding.SeverityMedium,
		confidence: finding.ConfidenceHigh,
		title:      "Apache password file",
		desc:       "An .htpasswd file was found containing hashed passwords for HTTP authentication.",
		remediate:  "Remove the file and add '.htpasswd' to .gitignore. Manage authentication credentials outside version control.",
	},
	{
		match:      exactNameAny(".netrc", "_netrc"),
		severity:   finding.SeverityMedium,
		confidence: finding.ConfidenceHigh,
		title:      "Netrc credentials file",
		desc:       "A .netrc file was found. These files store login credentials for remote hosts.",
		remediate:  "Remove the file and add '.netrc' to .gitignore.",
	},
	{
		match:      exactName(".pgpass"),
		severity:   finding.SeverityMedium,
		confidence: finding.ConfidenceHigh,
		title:      "PostgreSQL password file",
		desc:       "A .pgpass file was found containing PostgreSQL connection credentials.",
		remediate:  "Remove the file and add '.pgpass' to .gitignore. Use environment variables for database credentials.",
	},
	{
		match:      exactNameAny(".npmrc", ".pypirc"),
		severity:   finding.SeverityMedium,
		confidence: finding.ConfidenceMedium,
		title:      "Package manager credentials",
		desc:       "A package manager configuration file was found that may contain authentication tokens for package registries.",
		remediate:  "Remove the file if it contains auth tokens and add it to .gitignore. Use environment variables for registry authentication.",
	},

	// === Configuration that may contain secrets (medium confidence) ===
	{
		match:      nameContainsNonCode("credentials"),
		severity:   finding.SeverityMedium,
		confidence: finding.ConfidenceMedium,
		title:      "Potential credentials file",
		desc:       "A file with 'credentials' in its name was found. It may contain authentication data.",
		remediate:  "Review the file contents. If it contains real credentials, remove it and add the filename to .gitignore.",
	},
	{
		match:      nameContainsNonCode("secret"),
		severity:   finding.SeverityMedium,
		confidence: finding.ConfidenceLow,
		title:      "Potential secrets file",
		desc:       "A file with 'secret' in its name was found. It may contain sensitive configuration.",
		remediate:  "Review the file contents. If it contains secrets, remove it and add the filename to .gitignore.",
	},
}

const (
	sensitiveCheckID      = "FILE-001"
	sensitiveCheckName    = "sensitive-file-detection"
	sensitiveCheckVersion = "0.1.0"
)

func (c *SensitiveFileCheck) Meta() Meta {
	return Meta{
		ID:          sensitiveCheckID,
		Name:        sensitiveCheckName,
		Category:    finding.CategoryFiles,
		Description: "Detects files with names indicating sensitive content such as private keys, credentials, or environment files",
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
