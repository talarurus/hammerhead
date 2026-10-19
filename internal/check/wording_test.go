package check_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/talarurus/hammerhead/internal/check"
	"github.com/talarurus/hammerhead/internal/engine"
	"github.com/talarurus/hammerhead/internal/finding"
	"github.com/talarurus/hammerhead/internal/fs"
)

func TestFilenameWording_Conditional(t *testing.T) {
	cases := []struct {
		name, title, description string
		severity                 finding.Severity
		confidence               finding.Confidence
	}{
		{"id_rsa", "Potential SSH private key file", "The filename matches id_rsa, a name commonly used for SSH private keys. This is a filename-only match; contents were not inspected.", finding.SeverityHigh, finding.ConfidenceHigh},
		{"id_dsa", "Potential SSH private key file (DSA)", "The filename matches id_dsa, a name commonly used for DSA SSH private keys. This is a filename-only match; contents were not inspected.", finding.SeverityHigh, finding.ConfidenceHigh},
		{"id_ecdsa", "Potential SSH private key file (ECDSA)", "The filename matches id_ecdsa, a name commonly used for ECDSA SSH private keys. This is a filename-only match; contents were not inspected.", finding.SeverityHigh, finding.ConfidenceHigh},
		{"id_ed25519", "Potential SSH private key file (Ed25519)", "The filename matches id_ed25519, a name commonly used for Ed25519 SSH private keys. This is a filename-only match; contents were not inspected.", finding.SeverityHigh, finding.ConfidenceHigh},
		{"cert.pem", "Potential PEM key or certificate file", "The filename has a .pem extension, which may indicate a private key, a public certificate, or other data. This is a filename-only match; contents were not inspected.", finding.SeverityHigh, finding.ConfidenceMedium},
		{"server.key", "Potential private key file", "The filename has a .key extension, which may indicate a private key or unrelated data. This is a filename-only match; contents were not inspected.", finding.SeverityHigh, finding.ConfidenceMedium},
		{"cert.p12", "Potential PKCS#12 keystore file", "The filename has a .p12 or .pfx extension, which may indicate a keystore. This is a filename-only match; contents were not inspected.", finding.SeverityHigh, finding.ConfidenceHigh},
		{"app.jks", "Potential Java keystore file", "The filename has a .jks or .keystore extension, which may indicate a Java keystore. This is a filename-only match; contents were not inspected.", finding.SeverityHigh, finding.ConfidenceMedium},
		{".env.production", "Potential environment configuration file", "The filename matches a supported .env naming pattern, which may indicate environment configuration. This is a filename-only match; contents were not inspected.", finding.SeverityMedium, finding.ConfidenceHigh},
		{".htpasswd", "Potential Apache password file", "The filename matches .htpasswd, a name commonly used for HTTP authentication password hashes. This is a filename-only match; contents were not inspected.", finding.SeverityMedium, finding.ConfidenceHigh},
		{"_netrc", "Potential Netrc credentials file", "The filename matches .netrc or _netrc, names commonly used for remote-host login configuration. This is a filename-only match; contents were not inspected.", finding.SeverityMedium, finding.ConfidenceHigh},
		{".pgpass", "Potential PostgreSQL password file", "The filename matches .pgpass, a name commonly used for PostgreSQL connection credentials. This is a filename-only match; contents were not inspected.", finding.SeverityMedium, finding.ConfidenceHigh},
		{".npmrc", "Potential package manager credentials file", "The filename matches .npmrc or .pypirc, names used for package manager configuration that may include authentication tokens. This is a filename-only match; contents were not inspected.", finding.SeverityMedium, finding.ConfidenceMedium},
		{"aws_credentials.txt", "Potential credentials file", "The filename contains credentials, which may indicate authentication data. This is a filename-only match; contents were not inspected.", finding.SeverityMedium, finding.ConfidenceMedium},
		{"my_secret_token.txt", "Potential secrets file", "The filename contains secret, which may indicate sensitive configuration. This is a filename-only match; contents were not inspected.", finding.SeverityMedium, finding.ConfidenceLow},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// A benign or empty file still triggers the filename heuristic.
			// No contents are available to justify a stronger claim.
			sc := scWithFile(tc.name)
			sc.ReadFile = func(string, int64) fs.ReadOutcome {
				t.Fatal("filename rule must not inspect contents")
				return fs.ReadOutcome{}
			}
			findings, err := runCheckForTest(&check.SensitiveFileCheck{}, sc)
			if err != nil || len(findings) != 1 {
				t.Fatalf("findings=%+v err=%v", findings, err)
			}
			f := findings[0]
			assertWording(t, f, tc.title, tc.description,
				"Review the actual contents. If sensitive information is present, keep it outside version control and add an appropriate ignore pattern. Determine whether exposure occurred before deciding on credential rotation or other recovery steps.")
			if f.ID != finding.GenerateID("FILE-001", tc.name) || f.Path != tc.name || f.Evidence != tc.name || f.Line != 0 ||
				f.Severity != tc.severity || f.Confidence != tc.confidence || f.Class != finding.ClassSecurity || f.CheckVer != "0.2.0" {
				t.Fatalf("filename detection metadata changed: %+v", f)
			}
		})
	}
}

func TestSecretWording_ObservationNotVerification(t *testing.T) {
	// Header-only input cannot establish a parseable or usable key. Exercise
	// every supported header, including the generic and encrypted forms.
	for _, kind := range []string{"", "RSA ", "EC ", "OPENSSH ", "DSA ", "ENCRYPTED "} {
		t.Run("header/"+kind, func(t *testing.T) {
			header := "-----" + "BEGIN " + kind + "PRIVATE KEY-----"
			f := oneSecretFinding(t, "note.txt", "comment\n"+header+"\nnot-key-data")
			assertWording(t, f, "Supported private-key header detected",
				fmt.Sprintf("A supported private-key header (%s) was detected in file content. The header alone does not establish that the file contains a valid or usable private key. Tracking, exposure, and compromise were not established.", header),
				"Review the contents to determine whether this is a real private key. If so, keep it outside shared source files and determine whether exposure occurred. If exposure is confirmed, replace the affected key and review its use.")
			if f.ID != finding.GenerateID("SEC-001", "note.txt:2") || f.Line != 2 || f.Severity != finding.SeverityHigh || f.Confidence != finding.ConfidenceHigh || f.Evidence != header+" [KEY DATA REDACTED]" {
				t.Fatalf("header detection metadata changed: %+v", f)
			}
		})
	}
	for _, prefix := range []string{"AKIA", "ASIA"} {
		for _, withSecret := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/cooccurrence=%t", prefix, withSecret), func(t *testing.T) {
				key := prefix + "1234567890ABCDEF"
				secret := strings.Repeat("Z", 40)
				content := "example identifier\n" + key + "\n"
				if withSecret {
					// Same-file distance and unrelated text do not establish pairing.
					content += strings.Repeat("unrelated text\n", 20) + "secret_key=" + secret + "\n"
				}
				f := oneSecretFinding(t, "notes.txt", content)
				suffix := ":id"
				severity, confidence := finding.SeverityMedium, finding.ConfidenceMedium
				evidence := prefix + "****************"
				if withSecret {
					suffix = ":pair"
					severity, confidence = finding.SeverityCritical, finding.ConfidenceHigh
					evidence += " [SECRET KEY REDACTED]"
					assertWording(t, f, "AWS-shaped ID and secret assignment in the same file",
						fmt.Sprintf("An AWS-shaped Access Key ID ('%s...') and a supported 40-character secret assignment were detected in the same file. This does not establish that they match, are valid or active, were committed or exposed, or have been compromised.", prefix),
						"Verify whether these values are real credentials and whether they belong together. If sensitive, keep them outside shared source files. Determine whether exposure occurred; if confirmed, revoke or rotate the affected credentials and review their use.")
				} else {
					assertWording(t, f, "Potential AWS Access Key ID detected in file content",
						fmt.Sprintf("An AWS-shaped Access Key ID ('%s...') was detected in file content, without a supported non-example secret assignment detected in the same file. The identifier alone does not grant access. Validity, activity, tracking, exposure, and compromise were not established.", prefix),
						"Review whether this value is a real credential identifier and whether related secret material is handled securely. Determine whether any sensitive material was exposed before deciding on credential rotation or other recovery steps.")
				}
				if f.ID != finding.GenerateID("SEC-001", "notes.txt:2"+suffix) || f.Line != 2 || f.Severity != severity || f.Confidence != confidence || f.Evidence != evidence {
					t.Fatalf("AWS detection metadata changed: %+v", f)
				}
				encoded, err := json.Marshal(f)
				if err != nil {
					t.Fatal(err)
				}
				for _, raw := range []string{key, secret} {
					if strings.Contains(string(encoded), raw) {
						t.Fatalf("raw synthetic credential leaked in finding JSON")
					}
				}
			})
		}
	}
}

func oneSecretFinding(t *testing.T, path, content string) finding.Finding {
	t.Helper()
	findings, err := runCheckForTest(&check.SecretPatternCheck{}, scWithFileContent(path, content))
	if err != nil || len(findings) != 1 {
		t.Fatalf("findings=%+v err=%v", findings, err)
	}
	f := findings[0]
	if f.RuleID != "SEC-001" || f.Class != finding.ClassSecurity || f.CheckVer != "0.2.0" {
		t.Fatalf("metadata changed: %+v", f)
	}
	return f
}

func TestLargeFileWording_NoCommitClaim(t *testing.T) {
	for _, threshold := range []int64{10 * 1024 * 1024, check.DefaultLargeFileThreshold} {
		t.Run(fmt.Sprint(threshold), func(t *testing.T) {
			sc := &check.ScanContext{
				RepoRoot: t.TempDir(), // Ordinary directory, no Git history evidence.
				Options:  check.CheckOptions{LargeFileThresholdBytes: threshold},
				Files: []check.FileInfo{
					{Path: "below.bin", Size: threshold - 1},
					{Path: "equal.bin", Size: threshold},
					{Path: "above.bin", Size: threshold + 1024*1024},
					{Path: "directory", Size: threshold + 1, IsDir: true},
				},
			}
			findings, err := runCheckForTest(&check.LargeFileCheck{}, sc)
			if err != nil || len(findings) != 1 {
				t.Fatalf("findings=%+v err=%v", findings, err)
			}
			f := findings[0]
			assertWording(t, f, "Large file in audited directory",
				fmt.Sprintf("A file of %.2f MB was found in the audited directory, exceeding the configured size threshold. This size observation does not establish whether the file is tracked, committed, pushed, or included in repository history.", float64(threshold+1024*1024)/(1024*1024)),
				"Review whether the file belongs in version control. If it should remain local, add an appropriate ignore pattern and separately review any existing tracking. If it must be shared, consider Git LFS or external object storage.")
			if f.ID != finding.GenerateID("FILE-002", "above.bin") || f.Path != "above.bin" || f.Class != finding.ClassHygiene || f.Severity != finding.SeverityLow || f.Confidence != finding.ConfidenceHigh || f.CheckVer != "0.2.0" {
				t.Fatalf("large-file detection metadata changed: %+v", f)
			}
		})
	}
}

func TestGitignoreWording_TextualHeuristic(t *testing.T) {
	sc := scWithFileContent(".gitignore", "# custom policies may work without a supported spelling\n/local-env/\n")
	sc.Inventory = &fs.Inventory{RootGitignore: fs.PresencePresent}
	findings, err := runCheckForTest(&check.GitignoreCheck{}, sc)
	if err != nil || len(findings) != 2 {
		t.Fatalf("findings=%+v err=%v", findings, err)
	}
	for _, f := range findings {
		if !strings.HasPrefix(f.Title, "Supported textual ignore pattern not found: ") ||
			!strings.Contains(f.Description, "This heuristic does not evaluate Git's effective ignore behavior, other ignore sources, negations, or tracking state.") ||
			!strings.Contains(f.Remediation, "add appropriate patterns if needed") ||
			!strings.Contains(f.Remediation, "ignore patterns alone do not untrack files") ||
			!strings.HasPrefix(f.Evidence, "Supported textual pattern not found for: ") || f.CheckVer != "0.2.0" {
			t.Fatalf("heuristic wording exceeds evidence: %+v", f)
		}
	}
	// Preserve the existing heuristic even when a negation could defeat an
	// effective ignore rule. No claim about Git's effective behavior follows.
	sc = scWithFileContent(".gitignore", ".env\n!.env\n*.key\n!*.key\n")
	sc.Inventory = &fs.Inventory{RootGitignore: fs.PresencePresent}
	findings, err = runCheckForTest(&check.GitignoreCheck{}, sc)
	if err != nil || len(findings) != 0 {
		t.Fatalf("heuristic evaluation changed: %+v %v", findings, err)
	}
	findings, err = runCheckForTest(&check.GitignoreCheck{}, &check.ScanContext{Inventory: &fs.Inventory{RootGitignore: fs.PresenceAbsent}})
	if err != nil || len(findings) != 1 {
		t.Fatalf("missing-file findings=%+v err=%v", findings, err)
	}
	assertWording(t, findings[0], "Missing .gitignore file",
		"No .gitignore file was found at the audited root. Other ignore sources and Git tracking state were not evaluated by this check; this does not establish which files Git ignores.",
		"Review the project's ignore policy. If needed, create a root .gitignore with appropriate patterns for local environment files, private-key files, and build artifacts. Verify effective ignore behavior and review already-tracked files separately.")
}

func TestLicenseWording_PresenceDoesNotEstablishAdequacy(t *testing.T) {
	for _, presence := range []fs.PresenceFact{fs.PresenceAbsent, fs.PresencePresent, fs.PresenceUnknown} {
		sc := &check.ScanContext{Inventory: &fs.Inventory{RootREADME: fs.PresencePresent, RootLICENSE: presence}}
		sc.ReadFile = func(string, int64) fs.ReadOutcome {
			t.Fatal("presence check must not read license contents")
			return fs.ReadOutcome{}
		}
		findings, err := runCheckForTest(&check.RepoHygieneCheck{}, sc)
		if err != nil {
			t.Fatal(err)
		}
		if presence != fs.PresenceAbsent {
			if len(findings) != 0 {
				t.Fatalf("presence/unknown must not produce a license adequacy finding: %+v", findings)
			}
			continue
		}
		if len(findings) != 1 {
			t.Fatalf("findings=%+v", findings)
		}
		assertWording(t, findings[0], "Missing project LICENSE",
			"No recognized license filename was found at the audited root. License terms may be provided elsewhere. This check does not evaluate license contents, adequacy, or legal suitability, even when a recognized filename is present.",
			"Review where the project's license terms are documented and whether they are appropriate for its intended use. If needed, add a root license file with reviewed terms; a filename alone does not establish licensing rights.")
	}
}

func TestWording_CheckVersions(t *testing.T) {
	versions := map[string]string{"FILE-001": "0.2.0", "FILE-002": "0.2.0", "SEC-001": "0.2.0", "GIT-001": "0.2.0", "PROJ-001": "0.2.0", "PROJ-002": "0.1.0"}
	for _, c := range engine.DefaultRegistry().All() {
		meta := c.Meta()
		if meta.Version != versions[meta.ID] {
			t.Errorf("%s version=%s want %s", meta.ID, meta.Version, versions[meta.ID])
		}
	}
}

func assertWording(t *testing.T, f finding.Finding, title, description, remediation string) {
	t.Helper()
	if f.Title != title || f.Description != description || f.Remediation != remediation {
		t.Errorf("wording differs from reviewed observation and conditional guidance:\n%+v", f)
	}
}
