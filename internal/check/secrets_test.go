package check_test

import (
	"strings"
	"testing"

	"github.com/ammaarrehman/hammerhead/internal/check"
	"github.com/ammaarrehman/hammerhead/internal/finding"
	"github.com/ammaarrehman/hammerhead/internal/fs"
)

func TestSecretPatternCheck_PEMKey(t *testing.T) {
	c := &check.SecretPatternCheck{}

	header := "-----" + "BEGIN RSA PRIVATE KEY-----"
	footer := "-----" + "END RSA PRIVATE KEY-----"
	content := "package config\n\n// Server configuration\nconst privateKey = `" + header + "\nMIIEowIBAAKCAQEA0mockKeyContentHere\n" + footer + "`\n"

	sc := &check.ScanContext{
		RepoRoot: "/dummy",
		Files: []check.FileInfo{
			{Path: "config/keys.go", Size: int64(len(content)), IsDir: false},
		},
		ReadFile: func(p string, maxSize int64) fs.ReadOutcome {
			return fs.ReadOutcome{Status: fs.ReadStatusText, Data: []byte(content)}
		},
	}

	findings, err := runCheckForTest(c, sc)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for PEM key, got %d: %+v", len(findings), findings)
	}

	f := findings[0]
	if f.RuleID != "SEC-001" {
		t.Errorf("expected SEC-001, got %s", f.RuleID)
	}
	if f.Severity != finding.SeverityHigh {
		t.Errorf("expected SeverityHigh, got %v", f.Severity)
	}
	if f.Confidence != finding.ConfidenceHigh {
		t.Errorf("expected ConfidenceHigh, got %v", f.Confidence)
	}
	if f.Line != 4 {
		t.Errorf("expected line 4, got %d", f.Line)
	}
	if !strings.Contains(f.Evidence, "[KEY DATA REDACTED]") {
		t.Errorf("evidence not properly redacted: %s", f.Evidence)
	}
}

func TestSecretPatternCheck_AWSAccessKeyOnly(t *testing.T) {
	c := &check.SecretPatternCheck{}

	mockKey := "AKIA" + "1234567890ABCDEF"
	content := "AWS_REGION=us-east-1\nAWS_ACCESS_KEY_ID=" + mockKey + "\n"

	sc := &check.ScanContext{
		RepoRoot: "/dummy",
		Files: []check.FileInfo{
			{Path: "deploy.env", Size: int64(len(content)), IsDir: false},
		},
		ReadFile: func(p string, maxSize int64) fs.ReadOutcome {
			return fs.ReadOutcome{Status: fs.ReadStatusText, Data: []byte(content)}
		},
	}

	findings, err := runCheckForTest(c, sc)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for AWS Access Key ID alone, got %d: %+v", len(findings), findings)
	}

	f := findings[0]
	if f.Severity != finding.SeverityMedium {
		t.Errorf("expected SeverityMedium for AWS Access Key ID alone, got %v", f.Severity)
	}
	if f.Confidence != finding.ConfidenceMedium {
		t.Errorf("expected ConfidenceMedium, got %v", f.Confidence)
	}
	if !strings.Contains(f.Title, "Potential AWS Access Key ID") {
		t.Errorf("expected title to indicate potential identifier, got %q", f.Title)
	}
	if f.Line != 2 {
		t.Errorf("expected line 2, got %d", f.Line)
	}
	// Verify redaction: must NOT print unredacted key
	if f.Evidence != "AKIA****************" {
		t.Errorf("evidence must redact key, got %q", f.Evidence)
	}
}

func TestSecretPatternCheck_AWSCredentialPair(t *testing.T) {
	c := &check.SecretPatternCheck{}

	mockKey := "AKIA" + "1234567890ABCDEF"
	mockSecret := "wJalrXUtn" + "FEMI/K7MDENG/bPx" + "RfiCY1234567890" // 40 chars
	content := "AWS_REGION=us-east-1\nAWS_ACCESS_KEY_ID=" + mockKey + "\nAWS_SECRET_ACCESS_KEY=" + mockSecret + "\n"

	sc := &check.ScanContext{
		RepoRoot: "/dummy",
		Files: []check.FileInfo{
			{Path: "deploy.env", Size: int64(len(content)), IsDir: false},
		},
		ReadFile: func(p string, maxSize int64) fs.ReadOutcome {
			return fs.ReadOutcome{Status: fs.ReadStatusText, Data: []byte(content)}
		},
	}

	findings, err := runCheckForTest(c, sc)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for AWS credential pair, got %d: %+v", len(findings), findings)
	}

	f := findings[0]
	if f.Severity != finding.SeverityCritical {
		t.Errorf("expected SeverityCritical for AWS credential pair, got %v", f.Severity)
	}
	if f.Confidence != finding.ConfidenceHigh {
		t.Errorf("expected ConfidenceHigh, got %v", f.Confidence)
	}
	if !strings.Contains(f.Title, "AWS credential pair") {
		t.Errorf("expected title to indicate credential pair, got %q", f.Title)
	}
	// Verify redaction: secret MUST be completely omitted/redacted from evidence and description
	if strings.Contains(f.Evidence, mockSecret) {
		t.Errorf("secret key leaked in evidence: %q", f.Evidence)
	}
	if strings.Contains(f.Description, mockSecret) {
		t.Errorf("secret key leaked in description: %q", f.Description)
	}
	if f.Evidence != "AKIA**************** [SECRET KEY REDACTED]" {
		t.Errorf("evidence must redact both key and secret, got %q", f.Evidence)
	}
}

func TestSecretPatternCheck_PublicCertNotFlagged(t *testing.T) {
	c := &check.SecretPatternCheck{}

	content := "-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIBAgIJALa1234567890\n-----END CERTIFICATE-----\n"

	sc := &check.ScanContext{
		RepoRoot: "/dummy",
		Files: []check.FileInfo{
			{Path: "certs/ca.pem", Size: int64(len(content)), IsDir: false},
		},
		ReadFile: func(p string, maxSize int64) fs.ReadOutcome {
			return fs.ReadOutcome{Status: fs.ReadStatusText, Data: []byte(content)}
		},
	}

	findings, err := runCheckForTest(c, sc)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("public certificate .pem should not be flagged by SEC-001, got %d findings: %+v", len(findings), findings)
	}
}

func TestSecretPatternCheck_AWSExampleExemption(t *testing.T) {
	c := &check.SecretPatternCheck{}

	// Official AWS doc example key
	content := `# Example configuration from AWS docs
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
`

	sc := &check.ScanContext{
		RepoRoot: "/dummy",
		Files: []check.FileInfo{
			{Path: "README.md", Size: int64(len(content)), IsDir: false},
		},
		ReadFile: func(p string, maxSize int64) fs.ReadOutcome {
			return fs.ReadOutcome{Status: fs.ReadStatusText, Data: []byte(content)}
		},
	}

	findings, err := runCheckForTest(c, sc)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("expected AWS documentation example key to be exempted, got %d findings: %+v", len(findings), findings)
	}
}

func TestSecretPatternCheck_BenignContent(t *testing.T) {
	c := &check.SecretPatternCheck{}

	content := `package main

import "fmt"

func main() {
	fmt.Println("No secrets here!")
}
`

	sc := &check.ScanContext{
		RepoRoot: "/dummy",
		Files: []check.FileInfo{
			{Path: "main.go", Size: int64(len(content)), IsDir: false},
		},
		ReadFile: func(p string, maxSize int64) fs.ReadOutcome {
			return fs.ReadOutcome{Status: fs.ReadStatusText, Data: []byte(content)}
		},
	}

	findings, err := runCheckForTest(c, sc)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for benign code, got %d", len(findings))
	}
}

func TestSecretPatternCheck_WordBoundaryPreserved(t *testing.T) {
	c := &check.SecretPatternCheck{}

	content := "AWS_ACCESS_KEY_ID=A" + "AKIA" + "1234567890ABCDEF\n" +
		"ANOTHER_VAR=X" + "AKIA" + "1234567890ABCDEF then valid " + "AKIA" + "0987654321ABCDEF\n" +
		"MULTI=" + "AKIA" + "1111111111ABCDEF, " + "AKIA" + "2222222222ABCDEF\n" +
		"DOC_KEY=" + "AKIA" + "IOSFODNN7EXAMPLE\n"

	sc := &check.ScanContext{
		RepoRoot: "/dummy",
		Files: []check.FileInfo{
			{Path: "boundaries.env", Size: int64(len(content)), IsDir: false},
		},
		ReadFile: func(p string, maxSize int64) fs.ReadOutcome {
			return fs.ReadOutcome{Status: fs.ReadStatusText, Data: []byte(content)}
		},
	}

	findings, err := runCheckForTest(c, sc)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(findings))
	}

	if findings[0].Line != 2 || !strings.Contains(findings[0].Evidence, "AKIA****************") {
		t.Errorf("finding 1 mismatch: line %d, evidence %s", findings[0].Line, findings[0].Evidence)
	}
	if findings[1].Line != 3 || !strings.Contains(findings[1].Evidence, "AKIA****************") {
		t.Errorf("finding 2 mismatch: line %d, evidence %s", findings[1].Line, findings[1].Evidence)
	}
	if findings[2].Line != 3 || !strings.Contains(findings[2].Evidence, "AKIA****************") {
		t.Errorf("finding 3 mismatch: line %d, evidence %s", findings[2].Line, findings[2].Evidence)
	}
}

func TestSecretPatternCheck_FirstPEMHeaderPerFile(t *testing.T) {
	c := &check.SecretPatternCheck{}

	header := "-----" + "BEGIN RSA PRIVATE KEY-----"
	footer := "-----" + "END RSA PRIVATE KEY-----"
	content := header + "\nDATA1\n" + footer + "\n" + header + "\nDATA2\n" + footer + "\n"

	sc := &check.ScanContext{
		RepoRoot: "/dummy",
		Files: []check.FileInfo{
			{Path: "config/keys.pem", Size: int64(len(content)), IsDir: false},
		},
		ReadFile: func(p string, maxSize int64) fs.ReadOutcome {
			return fs.ReadOutcome{Status: fs.ReadStatusText, Data: []byte(content)}
		},
	}

	findings, err := runCheckForTest(c, sc)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for PEM key per file, got %d", len(findings))
	}
}
