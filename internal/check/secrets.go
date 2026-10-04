package check

import (
	"bytes"
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/ammaarrehman/hammerhead/internal/finding"
	"github.com/ammaarrehman/hammerhead/internal/fs"
)

const (
	secretCheckID      = "SEC-001"
	secretCheckName    = "secret-content-signatures"
	secretCheckVersion = "0.1.0"
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

// SecretPatternCheck inspects file contents for high-confidence credential signatures.
//
// Design principles:
//   - Strictly limited to unambiguous credential formats (PEM private keys, AWS credentials).
//   - An AWS Access Key ID by itself is an identifier (SeverityMedium). If both an Access Key ID
//     and an associated Secret Access Key are present in the same file context, it is classified
//     as a confirmed credential pair (SeverityCritical).
//   - Skips binary files and oversized files via SafeWalker protections.
//   - Never displays full secrets: all evidence snippets are redacted.
//   - Not an entropy scanner; does not purport to replace TruffleHog.
type SecretPatternCheck struct{}

func (c *SecretPatternCheck) Meta() Meta {
	return Meta{
		ID:          secretCheckID,
		Name:        secretCheckName,
		Category:    finding.CategorySecrets,
		Description: "Detects high-confidence secret signatures (PEM private keys, AWS access keys and credential pairs) in file contents",
		Version:     secretCheckVersion,
	}
}

func (c *SecretPatternCheck) Run(_ context.Context, sc *ScanContext) ([]finding.Finding, error) {
	var findings []finding.Finding

	for _, file := range sc.Files {
		if file.IsDir {
			continue
		}

		// Skip files larger than 5 MB for content regex scanning
		if file.Size > 5*1024*1024 {
			continue
		}

		// Check if file is binary before reading
		if file.AbsPath != "" {
			isBin, err := fs.IsBinaryFile(file.AbsPath)
			if err == nil && isBin {
				continue
			}
		}

		data, err := sc.ReadFile(file.Path)
		if err != nil {
			// Skip unreadable files without failing the entire audit
			continue
		}

		// Scan 1: PEM Private Key Header
		if loc := pemPrivateKeyRegex.FindIndex(data); loc != nil {
			lineNum := bytes.Count(data[:loc[0]], []byte("\n")) + 1
			matchedHeader := string(data[loc[0]:loc[1]])

			findings = append(findings, finding.Finding{
				ID:          finding.GenerateID(secretCheckID, fmt.Sprintf("%s:%d", file.Path, lineNum)),
				RuleID:      secretCheckID,
				Class:       finding.ClassSecurity,
				Category:    finding.CategorySecrets,
				Severity:    finding.SeverityHigh,
				Confidence:  finding.ConfidenceHigh,
				Title:       "Cryptographic private key in file content",
				Description: fmt.Sprintf("A PEM-encoded private key header (%s) was identified in file content. Committing private keys allows unauthorized actors to impersonate services or access encrypted data.", matchedHeader),
				Remediation: "Remove the private key from the repository and Git history immediately. Rotate all associated cryptographic certificates, SSH keys, or services.",
				Path:        file.Path,
				Line:        lineNum,
				Evidence:    fmt.Sprintf("%s [KEY DATA REDACTED]", matchedHeader),
				Source:      "hammerhead",
				CheckVer:    secretCheckVersion,
			})
		}

		// Scan 2: AWS Access Key ID & Credential Pairs
		keyMatches := awsAccessKeyRegex.FindAllSubmatchIndex(data, -1)
		if len(keyMatches) > 0 {
			// Check if file also contains an AWS Secret Access Key
			hasSecretKey := false
			secretMatches := awsSecretKeyRegex.FindAllSubmatchIndex(data, -1)
			for _, sm := range secretMatches {
				secVal := string(data[sm[2]:sm[3]])
				if secVal != awsDocSecretExample {
					hasSecretKey = true
					break
				}
			}

			for _, m := range keyMatches {
				keyID := string(data[m[2]:m[3]])

				// Exempt AWS's official documentation dummy key
				if keyID == awsDocKeyExample {
					continue
				}

				lineNum := bytes.Count(data[:m[2]], []byte("\n")) + 1
				redactedKey := keyID[:4] + strings.Repeat("*", len(keyID)-4)

				if hasSecretKey {
					// Case B: Access Key ID AND Secret Key present in the same file -> CRITICAL
					findings = append(findings, finding.Finding{
						ID:          finding.GenerateID(secretCheckID, fmt.Sprintf("%s:%d:pair", file.Path, lineNum)),
						RuleID:      secretCheckID,
						Class:       finding.ClassSecurity,
						Category:    finding.CategorySecrets,
						Severity:    finding.SeverityCritical,
						Confidence:  finding.ConfidenceHigh,
						Title:       "AWS credential pair (Access Key and Secret Key) committed to repository",
						Description: fmt.Sprintf("Both an AWS Access Key ID ('%s...') and a corresponding Secret Access Key assignment were identified in this file. Active credential pairs allow immediate programmatic authentication to AWS resources.", keyID[:4]),
						Remediation: "Immediately deactivate and delete this Access Key pair in the AWS IAM Console. Rotate any associated credentials and inspect AWS CloudTrail logs for unauthorized API activity.",
						Path:        file.Path,
						Line:        lineNum,
						Evidence:    fmt.Sprintf("%s [SECRET KEY REDACTED]", redactedKey),
						Source:      "hammerhead",
						CheckVer:    secretCheckVersion,
					})
				} else {
					// Case A: Access Key ID alone without verified secret key -> MEDIUM
					findings = append(findings, finding.Finding{
						ID:          finding.GenerateID(secretCheckID, fmt.Sprintf("%s:%d:id", file.Path, lineNum)),
						RuleID:      secretCheckID,
						Class:       finding.ClassSecurity,
						Category:    finding.CategorySecrets,
						Severity:    finding.SeverityMedium,
						Confidence:  finding.ConfidenceMedium,
						Title:       "Potential AWS Access Key ID committed to repository",
						Description: fmt.Sprintf("An AWS Access Key ID ('%s...') was identified in file content. This is a credential identifier and does not by itself grant access without the secret key. Hammerhead did not establish that a corresponding secret key is present in this file.", keyID[:4]),
						Remediation: "Verify whether this Access Key ID is active in the AWS IAM Console. If in use, ensure secret credentials are provided securely via environment variables or a secrets manager (e.g. AWS Secrets Manager or Vault) rather than committed files.",
						Path:        file.Path,
						Line:        lineNum,
						Evidence:    redactedKey,
						Source:      "hammerhead",
						CheckVer:    secretCheckVersion,
					})
				}
			}
		}
	}

	return findings, nil
}
