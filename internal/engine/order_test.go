package engine_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/talarurus/hammerhead/internal/check"
	"github.com/talarurus/hammerhead/internal/engine"
	"github.com/talarurus/hammerhead/internal/finding"
	"github.com/talarurus/hammerhead/internal/fs"
	"github.com/talarurus/hammerhead/internal/reporter"
	"github.com/talarurus/hammerhead/internal/scanstate"
)

// A test-only check supplies the same multiset in different arrival orders.
type orderFixtureCheck struct {
	id   string
	seed int64
	fail bool
}

func (c orderFixtureCheck) Meta() check.Meta { return check.Meta{ID: c.id, Version: "fixture"} }
func (c orderFixtureCheck) Run(ctx context.Context, sc *check.ScanContext) error {
	rng := rand.New(rand.NewSource(c.seed))
	if c.id == "PROJ-002" {
		local := *sc
		local.Files = slices.Clone(sc.Files)
		rng.Shuffle(len(local.Files), func(i, j int) { local.Files[i], local.Files[j] = local.Files[j], local.Files[i] })
		return (&check.ProjectDetectCheck{}).Run(ctx, &local)
	}
	findings := []finding.Finding{}
	for _, line := range []int{10, 2, 2} {
		findings = append(findings, finding.Finding{ID: "identical-id", RuleID: c.id, Class: finding.ClassSecurity, Severity: finding.SeverityHigh, Path: "same/path", Line: line, Title: "fixture", Description: "same ID retained", Source: "fixture", CheckVer: "fixture"})
	}
	rng.Shuffle(len(findings), func(i, j int) { findings[i], findings[j] = findings[j], findings[i] })
	for _, f := range findings {
		if err := sc.Emit(f); err != nil {
			return err
		}
	}
	if c.fail {
		paths := []string{"z", "y", "x", "c", "b", "a"}
		rng.Shuffle(len(paths), func(i, j int) { paths[i], paths[j] = paths[j], paths[i] })
		for _, path := range paths {
			sc.Coverage.AddReason(scanstate.ReasonEligibleReadFailure, sc.Options.MaxExamplesPerReason, c.id+"/"+path)
			sc.Coverage.AddReason(scanstate.ReasonTraversalFailure, sc.Options.MaxExamplesPerReason, c.id+"/"+path)
		}
		return errors.New("fixture failure")
	}
	return nil
}

func nonTimeJSON(t *testing.T, result *engine.ScanResult) []byte {
	t.Helper()
	var buffer bytes.Buffer
	j := reporter.NewJSON()
	j.Writer = &buffer
	j.AppVersion = "fixed-G9-version"
	if err := j.Report(result); err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(buffer.Bytes(), &fields); err != nil {
		t.Fatal(err)
	}
	var timestamp string
	if err := json.Unmarshal(fields["timestamp"], &timestamp); err != nil {
		t.Fatal(err)
	}
	if _, err := time.Parse(time.RFC3339, timestamp); err != nil {
		t.Fatal(err)
	}
	delete(fields, "timestamp") // Root, version and every other report field are compared.
	encoded, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestEngine_ReportDeterminism(t *testing.T) {
	// Missing Git is a completed native scan with a bounded diagnostic; this also
	// removes changing host Git state from the deterministic fixture.
	t.Setenv("PATH", t.TempDir())
	root := t.TempDir()
	for _, path := range []string{"z/go.mod", "a/go.mod", "z/package.json", "a/package.json", "pyproject.toml", "Pipfile", "README.md", "LICENSE", ".gitignore", "fixture.key"} {
		full := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(full), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("synthetic fixture\n.env\n*.key\n*.pem\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	// More expected exclusions than the sample cap, created in reverse order.
	for i := 11; i >= 0; i-- {
		if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("%02d.omit", i)), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	limits := scanstate.ProductionLimits()
	limits.MaxDiagnosticSamples = 4
	limits.MaxExamplesPerReason = 2
	config := &engine.ScanConfig{Limits: &limits, ExcludePatterns: []string{"*.omit"}}
	rng := rand.New(rand.NewSource(9))
	for _, mode := range []string{"native-completed", "shuffled-completed", "shuffled-partial"} {
		t.Run(mode, func(t *testing.T) {
			var wantJSON []byte
			var wantSkipped []fs.SkippedEntry
			for run := 0; run < 30; run++ {
				reg := engine.DefaultRegistry()
				if mode != "native-completed" {
					reg = engine.NewRegistry()
					ids := []string{"R-Z", "R-A", "R-M", "PROJ-002"}
					rng.Shuffle(len(ids), func(i, j int) { ids[i], ids[j] = ids[j], ids[i] })
					for _, id := range ids {
						if err := reg.Add(orderFixtureCheck{id: id, seed: int64(run), fail: mode == "shuffled-partial"}); err != nil {
							t.Fatal(err)
						}
					}
				}
				result, err := engine.New(reg).Scan(context.Background(), root, config)
				if err != nil {
					t.Fatal(err)
				}
				wantStatus := scanstate.StatusCompleted
				if mode == "shuffled-partial" {
					wantStatus = scanstate.StatusPartial
				}
				if result.Status != wantStatus {
					t.Fatalf("status = %s", result.Status)
				}
				if !*result.Coverage.Traversal.InventoryComplete {
					t.Fatal("fixture must finish bounded traversal")
				}
				if len(result.Diagnostics)+len(result.Skipped) > limits.MaxDiagnosticSamples {
					t.Fatal("combined sample cap exceeded")
				}
				if len(result.Skipped) != 2 || result.Skipped[0].Path != "00.omit" || result.Skipped[1].Path != "01.omit" {
					t.Fatalf("skip sample selection changed: %+v", result.Skipped)
				}
				if mode != "native-completed" {
					duplicates := 0
					for _, f := range result.Findings {
						if f.ID == "identical-id" {
							duplicates++
						}
					}
					if duplicates != 9 {
						t.Fatalf("identical IDs collapsed: %d", duplicates)
					}
				}
				got := nonTimeJSON(t, result)
				if run == 0 {
					wantJSON = got
					wantSkipped = result.Skipped
				} else if !bytes.Equal(got, wantJSON) || !reflect.DeepEqual(result.Skipped, wantSkipped) {
					t.Fatalf("run %d changed non-time report\n%s\nwant\n%s", run, got, wantJSON)
				}
			}
		})
	}
}
