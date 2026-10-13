//go:build darwin || linux

package git

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMetadata_InertDottedBranchRoundTrip(t *testing.T) {
	root, r := metadataFixture(t, false)
	for _, name := range []string{"v0.2-dev", "release/1.2", "feature.foo", "main"} {
		for _, setting := range []string{"remote", "merge"} {
			fixtureCommand(t, r, root, "config", "branch."+name+"."+setting, "opaque-not-live")
		}
	}
	v := preparedFixture(t, root, r)
	live, err := os.ReadFile(filepath.Join(v.dir, "config"))
	if err != nil || strings.Contains(string(live), "opaque-not-live") || strings.Contains(string(live), "branch") || strings.Contains(string(live), "remote") {
		t.Fatal("inert subsection reached live configuration", string(live), err)
	}
	native := fixtureCommand(t, r, root, metadataStatus...)
	controlled, err := v.Run(context.Background(), root, metadataStatus...)
	if err != nil || native != controlled {
		t.Fatalf("native=%q controlled=%q error=%v", native, controlled, err)
	}
	if err := v.verify(); err != nil {
		t.Fatal(err)
	}
}
