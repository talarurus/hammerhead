package check_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/ammaarrehman/hammerhead/internal/check"
	"github.com/ammaarrehman/hammerhead/internal/engine"
	"github.com/ammaarrehman/hammerhead/internal/finding"
	"github.com/ammaarrehman/hammerhead/internal/fs"
	"github.com/ammaarrehman/hammerhead/internal/git"
)

func createGitRepo(t *testing.T, makeDirty bool, detachHead bool) *check.ScanContext {
	t.Helper()
	dir := t.TempDir()

	runGit := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if err := cmd.Run(); err != nil {
			t.Fatalf("git %v failed: %v", args, err)
		}
	}

	runGit("init")
	runGit("config", "user.email", "test@example.com")
	runGit("config", "user.name", "Test User")

	if detachHead || !makeDirty {
		os.WriteFile(filepath.Join(dir, "README.md"), []byte("init"), 0644)
		runGit("add", "README.md")
		runGit("commit", "-m", "init")
	}

	if makeDirty {
		os.WriteFile(filepath.Join(dir, "dirty.txt"), []byte("dirty"), 0644)
	}

	if detachHead {
		runGit("checkout", "--detach")
	}

	snapshot, err := git.CollectSnapshot(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	return &check.ScanContext{RepoRoot: dir, Git: &snapshot}
}

func TestDefaultRegistry_RuleInventory(t *testing.T) {
	registry := engine.DefaultRegistry()
	checks := registry.All()

	if len(checks) != 7 {
		t.Fatalf("Expected exactly 7 registered checks, got %d", len(checks))
	}

	expectedIDs := map[string]bool{
		"FILE-001": true,
		"FILE-002": true,
		"GIT-001":  true,
		"GIT-002":  true,
		"PROJ-001": true,
		"PROJ-002": true,
		"SEC-001":  true,
	}

	for _, c := range checks {
		meta := c.Meta()
		if !expectedIDs[meta.ID] {
			t.Errorf("Unexpected check ID: %s", meta.ID)
		}
		delete(expectedIDs, meta.ID)
	}

	if len(expectedIDs) > 0 {
		t.Errorf("Missing check IDs: %v", expectedIDs)
	}
}

// TestCurrentRuleVariants uses synthetic ScanContext inputs to prove that
// every current detection path maps precisely to one of the 35 frozen variants.
func TestCurrentRuleVariants(t *testing.T) {
	tests := []struct {
		variantKey string
		checkFunc  func() check.Check
		setupSC    func(*testing.T) *check.ScanContext
		verify     func(*testing.T, []finding.Finding)
	}{
		// === FILE-001 ===
		{
			variantKey: "ssh-rsa",
			checkFunc:  func() check.Check { return &check.SensitiveFileCheck{} },
			setupSC:    func(t *testing.T) *check.ScanContext { return scWithFile("id_rsa") },
			verify:     verifyFinding("FILE-001", "Potential SSH private key file", finding.SeverityHigh),
		},
		{
			variantKey: "ssh-dsa",
			checkFunc:  func() check.Check { return &check.SensitiveFileCheck{} },
			setupSC:    func(t *testing.T) *check.ScanContext { return scWithFile("id_dsa") },
			verify:     verifyFinding("FILE-001", "Potential SSH private key file (DSA)", finding.SeverityHigh),
		},
		{
			variantKey: "ssh-ecdsa",
			checkFunc:  func() check.Check { return &check.SensitiveFileCheck{} },
			setupSC:    func(t *testing.T) *check.ScanContext { return scWithFile("id_ecdsa") },
			verify:     verifyFinding("FILE-001", "Potential SSH private key file (ECDSA)", finding.SeverityHigh),
		},
		{
			variantKey: "ssh-ed25519",
			checkFunc:  func() check.Check { return &check.SensitiveFileCheck{} },
			setupSC:    func(t *testing.T) *check.ScanContext { return scWithFile("id_ed25519") },
			verify:     verifyFinding("FILE-001", "Potential SSH private key file (Ed25519)", finding.SeverityHigh),
		},
		{
			variantKey: "pem-file",
			checkFunc:  func() check.Check { return &check.SensitiveFileCheck{} },
			setupSC:    func(t *testing.T) *check.ScanContext { return scWithFile("cert.pem") },
			verify:     verifyFinding("FILE-001", "Potential PEM key or certificate file", finding.SeverityHigh),
		},
		{
			variantKey: "key-file",
			checkFunc:  func() check.Check { return &check.SensitiveFileCheck{} },
			setupSC:    func(t *testing.T) *check.ScanContext { return scWithFile("server.key") },
			verify:     verifyFinding("FILE-001", "Potential private key file", finding.SeverityHigh),
		},
		{
			variantKey: "pkcs12-file",
			checkFunc:  func() check.Check { return &check.SensitiveFileCheck{} },
			setupSC:    func(t *testing.T) *check.ScanContext { return scWithFile("cert.p12") },
			verify:     verifyFinding("FILE-001", "Potential PKCS#12 keystore file", finding.SeverityHigh),
		},
		{
			variantKey: "java-keystore-file",
			checkFunc:  func() check.Check { return &check.SensitiveFileCheck{} },
			setupSC:    func(t *testing.T) *check.ScanContext { return scWithFile("app.jks") },
			verify:     verifyFinding("FILE-001", "Potential Java keystore file", finding.SeverityHigh),
		},
		{
			variantKey: "env-file",
			checkFunc:  func() check.Check { return &check.SensitiveFileCheck{} },
			setupSC:    func(t *testing.T) *check.ScanContext { return scWithFile(".env.production") },
			verify:     verifyFinding("FILE-001", "Potential environment configuration file", finding.SeverityMedium),
		},
		{
			variantKey: "htpasswd-file",
			checkFunc:  func() check.Check { return &check.SensitiveFileCheck{} },
			setupSC:    func(t *testing.T) *check.ScanContext { return scWithFile(".htpasswd") },
			verify:     verifyFinding("FILE-001", "Potential Apache password file", finding.SeverityMedium),
		},
		{
			variantKey: "netrc-file",
			checkFunc:  func() check.Check { return &check.SensitiveFileCheck{} },
			setupSC:    func(t *testing.T) *check.ScanContext { return scWithFile(".netrc") },
			verify:     verifyFinding("FILE-001", "Potential Netrc credentials file", finding.SeverityMedium),
		},
		{
			variantKey: "pgpass-file",
			checkFunc:  func() check.Check { return &check.SensitiveFileCheck{} },
			setupSC:    func(t *testing.T) *check.ScanContext { return scWithFile(".pgpass") },
			verify:     verifyFinding("FILE-001", "Potential PostgreSQL password file", finding.SeverityMedium),
		},
		{
			variantKey: "package-manager-config",
			checkFunc:  func() check.Check { return &check.SensitiveFileCheck{} },
			setupSC:    func(t *testing.T) *check.ScanContext { return scWithFile(".npmrc") },
			verify:     verifyFinding("FILE-001", "Potential package manager credentials file", finding.SeverityMedium),
		},
		{
			variantKey: "credentials-name",
			checkFunc:  func() check.Check { return &check.SensitiveFileCheck{} },
			setupSC:    func(t *testing.T) *check.ScanContext { return scWithFile("aws_credentials.txt") },
			verify:     verifyFinding("FILE-001", "Potential credentials file", finding.SeverityMedium),
		},
		{
			variantKey: "secret-name",
			checkFunc:  func() check.Check { return &check.SensitiveFileCheck{} },
			setupSC:    func(t *testing.T) *check.ScanContext { return scWithFile("my_secret_token.txt") },
			verify:     verifyFinding("FILE-001", "Potential secrets file", finding.SeverityMedium),
		},

		// === FILE-002 ===
		{
			variantKey: "large-file",
			checkFunc:  func() check.Check { return &check.LargeFileCheck{} },
			setupSC: func(t *testing.T) *check.ScanContext {
				return &check.ScanContext{
					Files: []check.FileInfo{{Path: "big.bin", Size: 60 * 1024 * 1024}}, // > 50MB
				}
			},
			verify: verifyFinding("FILE-002", "Large file in audited directory", finding.SeverityLow),
		},

		// === GIT-001 ===
		{
			variantKey: "missing-file",
			checkFunc:  func() check.Check { return &check.GitignoreCheck{} },
			setupSC: func(t *testing.T) *check.ScanContext {
				return &check.ScanContext{Inventory: &fs.Inventory{RootGitignore: fs.PresenceAbsent}, Files: []check.FileInfo{}}
			},
			verify: verifyFinding("GIT-001", "Missing .gitignore file", finding.SeverityLow),
		},
		{
			variantKey: "missing-env-pattern",
			checkFunc:  func() check.Check { return &check.GitignoreCheck{} },
			setupSC: func(t *testing.T) *check.ScanContext {
				sc := scWithFileContent(".gitignore", "*.key\n") // Missing env
				sc.Inventory = &fs.Inventory{RootGitignore: fs.PresencePresent}
				return sc
			},
			verify: verifyFinding("GIT-001", "Supported textual ignore pattern not found: Environment files", finding.SeverityLow),
		},
		{
			variantKey: "missing-key-pattern",
			checkFunc:  func() check.Check { return &check.GitignoreCheck{} },
			setupSC: func(t *testing.T) *check.ScanContext {
				sc := scWithFileContent(".gitignore", ".env\n") // Missing key
				sc.Inventory = &fs.Inventory{RootGitignore: fs.PresencePresent}
				return sc
			},
			verify: verifyFinding("GIT-001", "Supported textual ignore pattern not found: Private keys", finding.SeverityLow),
		},

		// === GIT-002 ===
		{
			variantKey: "dirty-worktree",
			checkFunc:  func() check.Check { return &check.GitHealthCheck{} },
			setupSC: func(t *testing.T) *check.ScanContext {
				return createGitRepo(t, true, false)
			},
			verify: verifyFinding("GIT-002", "Uncommitted changes in repository worktree", finding.SeverityInfo),
		},
		{
			variantKey: "detached-head",
			checkFunc:  func() check.Check { return &check.GitHealthCheck{} },
			setupSC: func(t *testing.T) *check.ScanContext {
				return createGitRepo(t, false, true)
			},
			verify: verifyFinding("GIT-002", "Repository in detached HEAD state", finding.SeverityInfo),
		},

		// === PROJ-001 ===
		{
			variantKey: "missing-readme",
			checkFunc:  func() check.Check { return &check.RepoHygieneCheck{} },
			setupSC: func(t *testing.T) *check.ScanContext {
				sc := scWithFile("LICENSE")
				sc.Inventory = &fs.Inventory{
					RootREADME:  fs.PresenceAbsent,
					RootLICENSE: fs.PresencePresent,
				}
				return sc
			},
			verify: verifyFinding("PROJ-001", "Missing project README", finding.SeverityLow),
		},
		{
			variantKey: "missing-license",
			checkFunc:  func() check.Check { return &check.RepoHygieneCheck{} },
			setupSC: func(t *testing.T) *check.ScanContext {
				sc := scWithFile("README.md")
				sc.Inventory = &fs.Inventory{
					RootREADME:  fs.PresencePresent,
					RootLICENSE: fs.PresenceAbsent,
				}
				return sc
			},
			verify: verifyFinding("PROJ-001", "Missing project LICENSE", finding.SeverityLow),
		},

		// === PROJ-002 ===
		{
			variantKey: "go",
			checkFunc:  func() check.Check { return &check.ProjectDetectCheck{} },
			setupSC:    func(t *testing.T) *check.ScanContext { return scWithFile("go.mod") },
			verify:     verifyFinding("PROJ-002", "Project runtime: Go", finding.SeverityInfo),
		},
		{
			variantKey: "node",
			checkFunc:  func() check.Check { return &check.ProjectDetectCheck{} },
			setupSC:    func(t *testing.T) *check.ScanContext { return scWithFile("package.json") },
			verify:     verifyFinding("PROJ-002", "Project runtime: Node.js / JavaScript / TypeScript", finding.SeverityInfo),
		},
		{
			variantKey: "python",
			checkFunc:  func() check.Check { return &check.ProjectDetectCheck{} },
			setupSC:    func(t *testing.T) *check.ScanContext { return scWithFile("requirements.txt") },
			verify:     verifyFinding("PROJ-002", "Project runtime: Python", finding.SeverityInfo),
		},
		{
			variantKey: "rust",
			checkFunc:  func() check.Check { return &check.ProjectDetectCheck{} },
			setupSC:    func(t *testing.T) *check.ScanContext { return scWithFile("Cargo.toml") },
			verify:     verifyFinding("PROJ-002", "Project runtime: Rust", finding.SeverityInfo),
		},
		{
			variantKey: "jvm",
			checkFunc:  func() check.Check { return &check.ProjectDetectCheck{} },
			setupSC:    func(t *testing.T) *check.ScanContext { return scWithFile("pom.xml") },
			verify:     verifyFinding("PROJ-002", "Project runtime: Java / JVM", finding.SeverityInfo),
		},
		{
			variantKey: "ruby",
			checkFunc:  func() check.Check { return &check.ProjectDetectCheck{} },
			setupSC:    func(t *testing.T) *check.ScanContext { return scWithFile("Gemfile") },
			verify:     verifyFinding("PROJ-002", "Project runtime: Ruby", finding.SeverityInfo),
		},
		{
			variantKey: "php",
			checkFunc:  func() check.Check { return &check.ProjectDetectCheck{} },
			setupSC:    func(t *testing.T) *check.ScanContext { return scWithFile("composer.json") },
			verify:     verifyFinding("PROJ-002", "Project runtime: PHP", finding.SeverityInfo),
		},
		{
			variantKey: "container",
			checkFunc:  func() check.Check { return &check.ProjectDetectCheck{} },
			setupSC:    func(t *testing.T) *check.ScanContext { return scWithFile("Dockerfile") },
			verify:     verifyFinding("PROJ-002", "Project runtime: Docker / Container", finding.SeverityInfo),
		},
		{
			variantKey: "terraform",
			checkFunc:  func() check.Check { return &check.ProjectDetectCheck{} },
			setupSC:    func(t *testing.T) *check.ScanContext { return scWithFile("main.tf") },
			verify:     verifyFinding("PROJ-002", "Project runtime: Terraform / IaC", finding.SeverityInfo),
		},

		// === SEC-001 ===
		{
			variantKey: "private-key-header",
			checkFunc:  func() check.Check { return &check.SecretPatternCheck{} },
			setupSC: func(t *testing.T) *check.ScanContext {
				return scWithFileContent("test.txt", "-----BEGIN RSA PRIVATE KEY-----\n")
			},
			verify: verifyFinding("SEC-001", "Supported private-key header detected", finding.SeverityHigh),
		},
		{
			variantKey: "aws-id",
			checkFunc:  func() check.Check { return &check.SecretPatternCheck{} },
			setupSC:    func(t *testing.T) *check.ScanContext { return scWithFileContent("test.txt", "AKIA1234567890123456") },
			verify:     verifyFinding("SEC-001", "Potential AWS Access Key ID detected in file content", finding.SeverityMedium),
		},
		{
			variantKey: "aws-id-secret-cooccurrence",
			checkFunc:  func() check.Check { return &check.SecretPatternCheck{} },
			setupSC: func(t *testing.T) *check.ScanContext {
				return scWithFileContent("test.txt", "AKIA1234567890123456\naws_secret_access_key=ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCD\n")
			},
			verify: verifyFinding("SEC-001", "AWS-shaped ID and secret assignment in the same file", finding.SeverityCritical),
		},
	}

	for _, tc := range tests {
		t.Run(tc.variantKey, func(t *testing.T) {
			if tc.setupSC == nil {
				t.Skip("Skipping non-synthetic test (handled by manual tests elsewhere)")
			}

			sc := tc.setupSC(t)
			c := tc.checkFunc()
			findings, err := runCheckForTest(c, sc)
			if err != nil {
				t.Fatalf("Unexpected check error: %v", err)
			}
			tc.verify(t, findings)
		})
	}

	// Test benign/exemption cases explicitly
	t.Run("benign_exemptions", func(t *testing.T) {
		// FILE-001 exemptions
		sc := scWithFile(".env.example")
		f, _ := runCheckForTest(&check.SensitiveFileCheck{}, sc)
		if len(f) != 0 {
			t.Errorf("Expected 0 findings for .env.example, got %d", len(f))
		}

		sc = scWithFile("secrets.go")
		f, _ = runCheckForTest(&check.SensitiveFileCheck{}, sc)
		if len(f) != 0 {
			t.Errorf("Expected 0 findings for secrets.go, got %d", len(f))
		}

		// SEC-001 exemptions
		sc = scWithFileContent("test.txt", "AKIAIOSFODNN7EXAMPLE\naws_secret_access_key="+"wJalrXUtn"+"FEMI/K7MDENG/bPx"+"RfiCYEXAMPLEKEY\n")
		f, _ = runCheckForTest(&check.SecretPatternCheck{}, sc)
		if len(f) != 0 {
			t.Errorf("Expected 0 findings for AWS documentation dummy keys, got %d", len(f))
		}

		// Priority behavior: my_secret_key.pem should trigger pem-file (high priority), not secret-name.
		sc = scWithFile("my_secret_key.pem")
		f, _ = runCheckForTest(&check.SensitiveFileCheck{}, sc)
		if len(f) != 1 {
			t.Fatalf("Expected 1 finding for my_secret_key.pem, got %d", len(f))
		}
		if f[0].Title != "Potential PEM key or certificate file" {
			t.Errorf("Expected priority match 'Potential PEM key or certificate file', got %q", f[0].Title)
		}
	})
}

// Helpers

func scWithFile(path string) *check.ScanContext {
	return &check.ScanContext{
		RepoRoot: ".",
		Files:    []check.FileInfo{{Path: path}},
	}
}

func scWithFileContent(path, content string) *check.ScanContext {
	return &check.ScanContext{
		RepoRoot: ".",
		Files:    []check.FileInfo{{Path: path}},
		ReadFile: func(p string, maxSize int64) fs.ReadOutcome {
			if p == path {
				return fs.ReadOutcome{Status: fs.ReadStatusText, Data: []byte(content)}
			}
			return fs.ReadOutcome{Status: fs.ReadStatusError, Err: os.ErrNotExist}
		},
	}
}

func verifyFinding(expectedRuleID, expectedTitle string, expectedSeverity finding.Severity) func(*testing.T, []finding.Finding) {
	return func(t *testing.T, findings []finding.Finding) {
		t.Helper()
		if len(findings) != 1 {
			t.Fatalf("Expected exactly 1 finding, got %d: %+v", len(findings), findings)
		}
		f := findings[0]
		if f.RuleID != expectedRuleID {
			t.Errorf("Expected RuleID %q, got %q", expectedRuleID, f.RuleID)
		}
		if f.Title != expectedTitle {
			t.Errorf("Expected Title %q, got %q", expectedTitle, f.Title)
		}
		if f.Severity != expectedSeverity {
			t.Errorf("Expected Severity %v, got %v", expectedSeverity, f.Severity)
		}
	}
}
