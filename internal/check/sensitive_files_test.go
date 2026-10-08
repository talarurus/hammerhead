package check_test

import (
	"testing"

	"github.com/ammaarrehman/hammerhead/internal/check"
	"github.com/ammaarrehman/hammerhead/internal/finding"
)

func TestSensitiveFileCheck_Detection(t *testing.T) {
	c := &check.SensitiveFileCheck{}

	files := []check.FileInfo{
		{Path: "src/main.go", IsDir: false},
		{Path: ".env", IsDir: false},
		{Path: ".env.example", IsDir: false},
		{Path: ".env.template", IsDir: false},
		{Path: "config/.env.local", IsDir: false},
		{Path: "keys/id_rsa", IsDir: false},
		{Path: "keys/id_ed25519", IsDir: false},
		{Path: "cert.pem", IsDir: false},
		{Path: "server.key", IsDir: false},
		{Path: "keystore.p12", IsDir: false},
		{Path: ".npmrc", IsDir: false},
		{Path: "id_rsa", IsDir: true}, // Directory named id_rsa should be ignored
	}

	sc := &check.ScanContext{
		RepoRoot: "/dummy",
		Files:    files,
	}

	findings, err := runCheckForTest(c, sc)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	foundPaths := make(map[string]finding.Finding)
	for _, f := range findings {
		foundPaths[f.Path] = f
	}

	// Should NOT flag src/main.go, .env.example, .env.template, or id_rsa directory
	if _, ok := foundPaths["src/main.go"]; ok {
		t.Errorf("src/main.go should not be flagged")
	}
	if _, ok := foundPaths[".env.example"]; ok {
		t.Errorf(".env.example should not be flagged")
	}
	if _, ok := foundPaths[".env.template"]; ok {
		t.Errorf(".env.template should not be flagged")
	}

	// Must flag .env
	envFinding, ok := foundPaths[".env"]
	if !ok {
		t.Errorf(".env was not flagged")
	} else {
		if envFinding.Severity != finding.SeverityMedium {
			t.Errorf(".env severity = %v, want Medium", envFinding.Severity)
		}
		if envFinding.Confidence != finding.ConfidenceHigh {
			t.Errorf(".env confidence = %v, want High", envFinding.Confidence)
		}
		if envFinding.Remediation == "" {
			t.Errorf(".env finding missing remediation")
		}
	}

	// Must flag config/.env.local
	if _, ok := foundPaths["config/.env.local"]; !ok {
		t.Errorf("config/.env.local was not flagged")
	}

	// Must flag keys/id_rsa
	rsaFinding, ok := foundPaths["keys/id_rsa"]
	if !ok {
		t.Errorf("keys/id_rsa was not flagged")
	} else {
		if rsaFinding.Severity != finding.SeverityHigh {
			t.Errorf("id_rsa severity = %v, want High", rsaFinding.Severity)
		}
		if rsaFinding.Confidence != finding.ConfidenceHigh {
			t.Errorf("id_rsa confidence = %v, want High", rsaFinding.Confidence)
		}
	}

	// Must flag cert.pem, server.key, keystore.p12, .npmrc
	expectedTriggered := []string{"cert.pem", "server.key", "keystore.p12", ".npmrc", "keys/id_ed25519"}
	for _, p := range expectedTriggered {
		if _, ok := foundPaths[p]; !ok {
			t.Errorf("expected %s to be flagged", p)
		}
	}

	// Directory named id_rsa should NOT be in findings
	countIDRsa := 0
	for _, f := range findings {
		if f.Path == "id_rsa" {
			countIDRsa++
		}
	}
	if countIDRsa != 0 {
		t.Errorf("directory named id_rsa was flagged as file finding")
	}
}

func TestSensitiveFileCheck_Meta(t *testing.T) {
	c := &check.SensitiveFileCheck{}
	meta := c.Meta()

	if meta.ID != "FILE-001" {
		t.Errorf("expected ID FILE-001, got %s", meta.ID)
	}
	if meta.Category != finding.CategoryFiles {
		t.Errorf("expected Category files, got %s", meta.Category)
	}
	if meta.Description == "" {
		t.Errorf("expected non-empty description")
	}
}
