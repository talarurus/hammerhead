package product_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Inspect all local production variants, not just the host's selected files.
// The companion release dependency audit rejects os/exec in the linked graph.
func TestCore_NoProcessOrGitImplementation(t *testing.T) {
	root := "../.."
	for _, excluded := range []string{"internal/git", "internal/check/git_health.go", "cmd/hammerhead"} {
		if _, err := os.Stat(filepath.Join(root, excluded)); !os.IsNotExist(err) {
			t.Fatalf("full-Git product source is present: %s (%v)", excluded, err)
		}
	}
	for _, dir := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
			if err != nil {
				return err
			}
			imports := map[string]string{}
			for _, i := range f.Imports {
				name, err := strconv.Unquote(i.Path.Value)
				if err != nil {
					return err
				}
				if name == "os/exec" || name == "plugin" || name == "C" || strings.Contains(name, "/internal/git") {
					t.Errorf("forbidden production import in %s: %s", path, name)
				}
				alias := filepath.Base(name)
				if i.Name != nil {
					alias = i.Name.Name
				}
				imports[alias] = name
			}
			ast.Inspect(f, func(n ast.Node) bool {
				s, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				id, ok := s.X.(*ast.Ident)
				if !ok {
					return true
				}
				pkg := imports[id.Name]
				if pkg == "os" || pkg == "syscall" || pkg == "golang.org/x/sys/unix" {
					switch s.Sel.Name {
					case "StartProcess", "ForkExec", "Exec", "Fexecve", "Execve":
						t.Errorf("process entrypoint in %s: %s.%s", path, pkg, s.Sel.Name)
					}
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
