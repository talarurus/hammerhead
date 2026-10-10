package git_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestGitBoundary_NoRawMetadataOrCheckExecution(t *testing.T) {
	// Enforce the leaf/data boundary in addition to FIFO and snapshot behavior.
	entries, err := os.ReadDir("../check")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		path := filepath.Join("../check", entry.Name())
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			name, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "os", "os/exec", "io/ioutil", "syscall", "golang.org/x/sys/unix", "github.com/ammaarrehman/hammerhead/internal/git":
				t.Errorf("check has filesystem/process authority: %s imports %s", path, name)
			}
		}
	}
	f, err := parser.ParseFile(token.NewFileSet(), "repo.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	ast.Inspect(f, func(n ast.Node) bool {
		if fn, ok := n.(*ast.FuncDecl); ok && (fn.Name.Name == "DetectRepoFallback" || fn.Name.Name == "readHeadBranch") {
			t.Error("raw fallback returned")
		}
		if sel, ok := n.(*ast.SelectorExpr); ok {
			if id, ok := sel.X.(*ast.Ident); ok && id.Name == "os" && sel.Sel.Name != "Lstat" && sel.Sel.Name != "ErrNotExist" {
				t.Errorf("raw metadata access: os.%s", sel.Sel.Name)
			}
		}
		return true
	})
}
