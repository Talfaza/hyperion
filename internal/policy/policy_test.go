// Package policy enforces Hyperion Trace's safety guarantees on the source
// tree: the scanner is read-only, never opens network connections, and runs
// external commands from exactly one hardened place.
package policy

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Imports no production file may use.
var forbiddenImports = map[string]string{
	"net":        "the scanner must not open network connections",
	"net/http":   "the scanner must not open network connections",
	"net/rpc":    "the scanner must not open network connections",
	"crypto/tls": "the scanner must not open network connections",
	"unsafe":     "memory safety",
	"os/signal":  "signal handling belongs to the CLI framework",
	"plugin":     "no dynamic code loading",
	"io/ioutil":  "deprecated; use platform.Host.ReadFile",
}

// Imports allowed only in specific files.
var restrictedImports = map[string][]string{
	"os/exec": {"internal/platform/exec.go"},
}

// os functions that modify the filesystem.
var forbiddenOSCalls = map[string]bool{
	"WriteFile": true, "Create": true, "CreateTemp": true, "Remove": true, "RemoveAll": true,
	"Mkdir": true, "MkdirAll": true, "MkdirTemp": true, "Rename": true, "Chmod": true,
	"Chown": true, "Lchown": true, "Chtimes": true, "Symlink": true, "Link": true,
	"Truncate": true, "Setenv": true, "Unsetenv": true, "Clearenv": true,
}

// Files allowed to call os.OpenFile (and only with read-only flags).
var openFileAllowed = map[string]bool{"internal/platform/fs.go": true}

func repoRoot(t *testing.T) string {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func productionFiles(t *testing.T) map[string]*ast.File {
	t.Helper()
	root := repoRoot(t)
	fset := token.NewFileSet()
	files := map[string]*ast.File{}
	for _, dir := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			f, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(root, path)
			files[filepath.ToSlash(rel)] = f
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(files) == 0 {
		t.Fatal("no source files found")
	}
	return files
}

func TestNoForbiddenImports(t *testing.T) {
	for path, f := range productionFiles(t) {
		for _, imp := range f.Imports {
			name, _ := strconv.Unquote(imp.Path.Value)
			if why := forbiddenImports[name]; why != "" {
				t.Errorf("%s imports %s: %s", path, name, why)
			}
			if allowed, ok := restrictedImports[name]; ok && !contains(allowed, path) {
				t.Errorf("%s imports %s; only %v may", path, name, allowed)
			}
		}
	}
}

func TestReadOnlyFilesystemAccess(t *testing.T) {
	for path, f := range productionFiles(t) {
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "os" {
				return true
			}
			switch {
			case forbiddenOSCalls[sel.Sel.Name]:
				t.Errorf("%s calls os.%s: the scanner must never modify the host", path, sel.Sel.Name)
			case sel.Sel.Name == "OpenFile":
				if !openFileAllowed[path] {
					t.Errorf("%s calls os.OpenFile; use platform.Host.ReadFile", path)
				} else if !readOnlyFlags(call) {
					t.Errorf("%s calls os.OpenFile without O_RDONLY", path)
				}
			}
			return true
		})
	}
}

// readOnlyFlags checks the flag argument mentions O_RDONLY and no write flag.
func readOnlyFlags(call *ast.CallExpr) bool {
	if len(call.Args) < 2 {
		return false
	}
	var names []string
	ast.Inspect(call.Args[1], func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok {
			names = append(names, id.Name)
		}
		return true
	})
	hasRead := false
	for _, n := range names {
		switch n {
		case "O_WRONLY", "O_RDWR", "O_CREATE", "O_CREAT", "O_TRUNC", "O_APPEND":
			return false
		case "O_RDONLY":
			hasRead = true
		}
	}
	return hasRead
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
