package check

import (
	"bytes"
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/talarurus/hammerhead/internal/finding"
	"github.com/talarurus/hammerhead/internal/fs"
	"github.com/talarurus/hammerhead/internal/scanstate"
)

const (
	secretCheckID      = "SEC-001"
	secretCheckName    = "secret-content-signatures"
	secretCheckVersion = "0.2.0"
)

// Content signatures: narrow, deterministic, high-confidence.
var (
	// pemPrivateKeyRegex matches standard PEM-encoded private key headers.
	pemPrivateKeyRegex = regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----`)

	// awsAccessKeyRegex matches AWS Access Key IDs (20 chars starting with AKIA or ASIA).
	awsAccessKeyRegex = regexp.MustCompile(`\b((?:AKIA|ASIA)[0-9A-Z]{16})\b`)

	// awsSecretKeyRegex matches standard configuration assignments of 40-character AWS Secret Access Keys.
	awsSecretKeyRegex = regexp.MustCompile(`(?i)(?:aws_secret_access_key|secret_access_key|secret_key|aws_secret)\s*[:=]\s*["']?([0-9a-zA-Z/+=]{40})["']?`)
)

// AWS documentation published example credentials.
const (
	awsDocKeyExample    = "AKIAIOSFODNN7EXAMPLE"
	awsDocSecretExample = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
)

// SecretPatternCheck inspects file contents for supported credential-shaped signatures.
//
// Design principles:
//   - Matches private-key headers and AWS-shaped identifiers/assignments, without validation.
//   - An AWS-shaped ID alone is SeverityMedium; same-file co-occurrence with a supported
//     secret assignment is SeverityCritical. Neither establishes a matching or active pair.
//   - The guarded reader classifies binary content; files over 5 MiB are ineligible.
//   - Never displays full secrets: all evidence snippets are redacted.
//   - Not an entropy scanner; does not purport to replace TruffleHog.
type SecretPatternCheck struct{}

func (c *SecretPatternCheck) Meta() Meta {
	return Meta{
		ID:          secretCheckID,
		Name:        secretCheckName,
		Category:    finding.CategorySecrets,
		Description: "Detects supported private-key headers and AWS-shaped IDs with optional same-file secret assignments; does not validate credentials",
		Version:     secretCheckVersion,
	}
}

func iterateAWSAccessKeys(ctx context.Context, data []byte, visit func(match awsMatch) error) error {
	hasSecretKeyChecked := false
	hasSecretKey := false

	keyOffset := 0
	for keyOffset < len(data) {
		if err := ctx.Err(); err != nil {
			return err
		}

		m := awsAccessKeyRegex.FindSubmatchIndex(data[keyOffset:])
		if m == nil {
			break
		}

		matchStart := m[0] + keyOffset
		matchEnd := m[1] + keyOffset
		subStart := m[2] + keyOffset
		subEnd := m[3] + keyOffset

		// Check false \b at the start of the slice
		if m[0] == 0 && keyOffset > 0 {
			if isWordChar(data[keyOffset-1]) {
				// False positive due to slice boundary acting as start of string
				keyOffset = matchStart + 1
				continue
			}
		}

		keyID := string(data[subStart:subEnd])

		// Exempt AWS's official documentation dummy key
		if keyID == awsDocKeyExample {
			keyOffset = matchEnd
			continue
		}

		if !hasSecretKeyChecked {
			hasSecretKeyChecked = true
			secOffset := 0
			for secOffset < len(data) {
				if err := ctx.Err(); err != nil {
					return err
				}
				sm := awsSecretKeyRegex.FindSubmatchIndex(data[secOffset:])
				if sm == nil {
					break
				}
				secVal := string(data[sm[2]+secOffset : sm[3]+secOffset])
				if secVal != awsDocSecretExample {
					hasSecretKey = true
					break
				}
				secOffset += sm[1]
			}
		}

		if err := visit(awsMatch{
			keyID:      keyID,
			matchStart: matchStart,
			matchEnd:   matchEnd,
			hasSecret:  hasSecretKey,
		}); err != nil {
			return err
		}

		keyOffset = matchEnd
	}
	return nil
}

type awsMatch struct {
	keyID      string
	matchStart int
	matchEnd   int
	hasSecret  bool
}

func (c *SecretPatternCheck) Run(ctx context.Context, sc *ScanContext) error {
	for _, file := range sc.Files {
		if err := ctx.Err(); err != nil {
			return err
		}

		if file.IsDir {
			continue
		}

		const maxEligibleSize = 5 * 1024 * 1024
		if file.Size > maxEligibleSize {
			continue
		}

		if sc.Coverage != nil {
			sc.Coverage.EligibleFiles++
		}

		// We use 5 MB as the eligibility boundary
		outcome := sc.ReadFile(file.Path, maxEligibleSize)
		if sc.Coverage != nil {
			sc.Coverage.ReadBytes += int(outcome.BytesRead)
		}

		if outcome.Status == fs.ReadStatusBudgetExhaust {
			return scanstate.ErrBudgetExhausted
		}

		if outcome.Status == fs.ReadStatusError {
			if sc.Coverage != nil {
				sc.Coverage.AddReason(scanstate.ReasonEligibleReadFailure, sc.Options.MaxExamplesPerReason, file.Path)
			}
			continue
		}

		// SEC-001 expected exclusions: binary files, too large, safety rejects
		if outcome.Status != fs.ReadStatusText {
			continue
		}

		if sc.Coverage != nil {
			sc.Coverage.InspectedFiles++
		}

		data := outcome.Data

		// Scan 1: PEM Private Key Header (FIRST supported key per file)
		if loc := pemPrivateKeyRegex.FindIndex(data); loc != nil {
			if err := ctx.Err(); err != nil {
				return err
			}
			matchStart := loc[0]
			matchEnd := loc[1]

			lineNum := bytes.Count(data[:matchStart], []byte("\n")) + 1
			matchedHeader := string(data[matchStart:matchEnd])

			err := sc.Emit(finding.Finding{
				ID:          finding.GenerateID(secretCheckID, fmt.Sprintf("%s:%d", file.Path, lineNum)),
				RuleID:      secretCheckID,
				Class:       finding.ClassSecurity,
				Category:    finding.CategorySecrets,
				Severity:    finding.SeverityHigh,
				Confidence:  finding.ConfidenceHigh,
				Title:       "Supported private-key header detected",
				Description: fmt.Sprintf("A supported private-key header (%s) was detected in file content. The header alone does not establish that the file contains a valid or usable private key. Tracking, exposure, and compromise were not established.", matchedHeader),
				Remediation: "Review the contents to determine whether this is a real private key. If so, keep it outside shared source files and determine whether exposure occurred. If exposure is confirmed, replace the affected key and review its use.",
				Path:        file.Path,
				Line:        lineNum,
				Evidence:    fmt.Sprintf("%s [KEY DATA REDACTED]", matchedHeader),
				Source:      "hammerhead",
				CheckVer:    secretCheckVersion,
			})
			if err != nil {
				return err
			}
		}

		// Scan 2: AWS-shaped IDs and same-file secret assignments
		err := iterateAWSAccessKeys(ctx, data, func(m awsMatch) error {
			lineNum := bytes.Count(data[:m.matchStart], []byte("\n")) + 1
			redactedKey := m.keyID[:4] + strings.Repeat("*", len(m.keyID)-4)

			if m.hasSecret {
				// Case B: Access Key ID AND Secret Key present in the same file -> CRITICAL
				return sc.Emit(finding.Finding{
					ID:          finding.GenerateID(secretCheckID, fmt.Sprintf("%s:%d:pair", file.Path, lineNum)),
					RuleID:      secretCheckID,
					Class:       finding.ClassSecurity,
					Category:    finding.CategorySecrets,
					Severity:    finding.SeverityCritical,
					Confidence:  finding.ConfidenceHigh,
					Title:       "AWS-shaped ID and secret assignment in the same file",
					Description: fmt.Sprintf("An AWS-shaped Access Key ID ('%s...') and a supported 40-character secret assignment were detected in the same file. This does not establish that they match, are valid or active, were committed or exposed, or have been compromised.", m.keyID[:4]),
					Remediation: "Verify whether these values are real credentials and whether they belong together. If sensitive, keep them outside shared source files. Determine whether exposure occurred; if confirmed, revoke or rotate the affected credentials and review their use.",
					Path:        file.Path,
					Line:        lineNum,
					Evidence:    fmt.Sprintf("%s [SECRET KEY REDACTED]", redactedKey),
					Source:      "hammerhead",
					CheckVer:    secretCheckVersion,
				})
			}

			// Case A: AWS-shaped ID without a supported non-example secret assignment -> MEDIUM
			return sc.Emit(finding.Finding{
				ID:          finding.GenerateID(secretCheckID, fmt.Sprintf("%s:%d:id", file.Path, lineNum)),
				RuleID:      secretCheckID,
				Class:       finding.ClassSecurity,
				Category:    finding.CategorySecrets,
				Severity:    finding.SeverityMedium,
				Confidence:  finding.ConfidenceMedium,
				Title:       "Potential AWS Access Key ID detected in file content",
				Description: fmt.Sprintf("An AWS-shaped Access Key ID ('%s...') was detected in file content, without a supported non-example secret assignment detected in the same file. The identifier alone does not grant access. Validity, activity, tracking, exposure, and compromise were not established.", m.keyID[:4]),
				Remediation: "Review whether this value is a real credential identifier and whether related secret material is handled securely. Determine whether any sensitive material was exposed before deciding on credential rotation or other recovery steps.",
				Path:        file.Path,
				Line:        lineNum,
				Evidence:    redactedKey,
				Source:      "hammerhead",
				CheckVer:    secretCheckVersion,
			})
		})
		if err != nil {
			return err
		}
	}

	return nil
}

func isWordChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'
}
